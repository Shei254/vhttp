/*
 * Copyright (c) 2015 DeNA Co., Ltd. Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/un.h>
#include "vhttp.h"
#include "vhttp/configurator.h"
#include "vhttp/serverutil.h"

struct fastcgi_configurator_t {
    vhttp_configurator_t super;
    vhttp_fastcgi_config_vars_t *vars;
    vhttp_fastcgi_config_vars_t _vars_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_timeout_io(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    return vhttp_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->io_timeout);
}

static int on_config_timeout_keepalive(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    return vhttp_configurator_scanf(cmd, node, "%" SCNu64, &self->vars->keepalive_timeout);
}

static int on_config_document_root(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;

    if (node->data.scalar[0] == '\0') {
        /* unset */
        self->vars->document_root = vhttp_iovec_init(NULL, 0);
    } else if (node->data.scalar[0] == '/') {
        /* set */
        self->vars->document_root = vhttp_iovec_init(node->data.scalar, strlen(node->data.scalar));
    } else {
        vhttp_configurator_errprintf(cmd, node, "value does not start from `/`");
        return -1;
    }
    return 0;
}

static int on_config_send_delegated_uri(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    ssize_t v;

    if ((v = vhttp_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    self->vars->send_delegated_uri = (int)v;
    return 0;
}

static int on_config_connect(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    const char *hostname = "127.0.0.1", *servname = NULL, *type = "tcp";

    /* fetch servname (and hostname) */
    switch (node->type) {
    case YOML_TYPE_SCALAR:
        servname = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t **port_node, **host_node, **type_node;
        if (vhttp_configurator_parse_mapping(cmd, node, "port:s", "host:s,type:s", &port_node, &host_node, &type_node) != 0)
            return -1;
        servname = (*port_node)->data.scalar;
        if (host_node != NULL)
            hostname = (*host_node)->data.scalar;
        if (type_node != NULL)
            type = (*type_node)->data.scalar;
    } break;
    default:
        vhttp_configurator_errprintf(cmd, node,
                                   "value must be a string or a mapping (with keys: `port` and optionally `host` and `type`)");
        return -1;
    }

    vhttp_url_t upstream;

    if (strcmp(type, "unix") == 0) {
        /* unix socket */
        struct sockaddr_un sa;
        if (strlen(servname) >= sizeof(sa.sun_path)) {
            vhttp_configurator_errprintf(cmd, node, "path:%s is too long as a unix socket name", servname);
            return -1;
        }
        vhttp_url_init_with_sun_path(&upstream, NULL, &vhttp_URL_SCHEME_FASTCGI, vhttp_iovec_init(servname, strlen(servname)),
                                   vhttp_iovec_init(vhttp_STRLIT("/")));
    } else if (strcmp(type, "tcp") == 0) {
        /* tcp socket */
        uint16_t port;
        if (sscanf(servname, "%" SCNu16, &port) != 1) {
            vhttp_configurator_errprintf(cmd, node, "invalid port number:%s", servname);
            return -1;
        }
        vhttp_url_init_with_hostport(&upstream, NULL, &vhttp_URL_SCHEME_FASTCGI, vhttp_iovec_init(hostname, strlen(hostname)), port,
                                   vhttp_iovec_init(vhttp_STRLIT("/")));
    } else {
        vhttp_configurator_errprintf(cmd, node, "unknown listen type: %s", type);
        return -1;
    }

    vhttp_fastcgi_register(ctx->pathconf, &upstream, self->vars);
    free(upstream.authority.base);

    return 0;
}

static int create_spawnproc(vhttp_configurator_command_t *cmd, yoml_t *node, const char *dirname, char *const *argv,
                            struct sockaddr_un *sa, struct passwd *pw)
{
    int ret, listen_fd = -1, pipe_fds[2] = {-1, -1};

    /* build socket path */
    sa->sun_family = AF_UNIX;
    ret = snprintf(sa->sun_path, sizeof(sa->sun_path), "%s/_", dirname);
    if (ret < 0 || ret >= sizeof(sa->sun_path)) {
        vhttp_configurator_errprintf(cmd, node, "unix socket path too long: %s", dirname);
        goto Error;
    }

    /* create socket */
    if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        vhttp_configurator_errprintf(cmd, node, "socket(2) failed: %s", strerror(errno));
        goto Error;
    }
    if (bind(listen_fd, (void *)sa, sizeof(*sa)) != 0) {
        vhttp_configurator_errprintf(cmd, node, "bind(2) failed: %s", strerror(errno));
        goto Error;
    }
    if (listen(listen_fd, vhttp_SOMAXCONN) != 0) {
        vhttp_configurator_errprintf(cmd, node, "listen(2) failed: %s", strerror(errno));
        goto Error;
    }
    /* change ownership of socket */
    if (pw != NULL && chown(sa->sun_path, pw->pw_uid, pw->pw_gid) != 0) {
        vhttp_configurator_errprintf(cmd, node, "chown(2) failed to change ownership of socket:%s:%s", sa->sun_path, strerror(errno));
        goto Error;
    }

    /* create pipe which is used to notify the termination of the server */
    if (pipe(pipe_fds) != 0) {
        vhttp_configurator_errprintf(cmd, node, "pipe(2) failed: %s", strerror(errno));
        pipe_fds[0] = -1;
        pipe_fds[1] = -1;
        goto Error;
    }
    if (fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC) < 0)
        goto Error;

    /* spawn, mapping listen_fd to fd 0, read-side of the pipe to fd 5 */
    int mapped_fds[] = {listen_fd, 0, -1, -1, -1};
    if (pipe_fds[0] != 5) {
        mapped_fds[2] = pipe_fds[0];
        mapped_fds[3] = 5;
    }
    pid_t pid = vhttp_spawnp(argv[0], argv, mapped_fds, 0);
    if (pid == -1) {
        vhttp_error_printf("[lib/handler/fastcgi.c] failed to launch helper program %s:%s\n", argv[0], strerror(errno));
        goto Error;
    }

    close(listen_fd);
    listen_fd = -1;
    close(pipe_fds[0]);
    pipe_fds[0] = -1;

    return pipe_fds[1];

Error:
    if (pipe_fds[0] != -1)
        close(pipe_fds[0]);
    if (pipe_fds[1])
        close(pipe_fds[1]);
    if (listen_fd != -1)
        close(listen_fd);
    unlink(sa->sun_path);
    return -1;
}

static void spawnproc_on_dispose(vhttp_fastcgi_handler_t *handler, void *data)
{
    int pipe_fd = (int)((char *)data - (char *)NULL);
    close(pipe_fd);
}

static int on_config_spawn(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)cmd->configurator;
    char *spawn_user = ctx->globalconf->user, *spawn_cmd;
    char *kill_on_close_cmd_path = NULL, *setuidgid_cmd_path = NULL;
    char dirname[] = "/tmp/vhttp.fcgisock.XXXXXX";
    char *argv[10];
    int spawner_fd;
    struct sockaddr_un sa;
    vhttp_fastcgi_config_vars_t config_vars;
    int ret = -1;
    struct passwd vhttp_user_pwbuf, *vhttp_user_pw;
    char vhttp_user_buf[65536];

    memset(&sa, 0, sizeof(sa));

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        spawn_cmd = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t **command_node, **user_node;
        if (vhttp_configurator_parse_mapping(cmd, node, "command:s", "user:s", &command_node, &user_node) != 0)
            return -1;
        spawn_cmd = (*command_node)->data.scalar;
        if (user_node != NULL)
            spawn_user = (*user_node)->data.scalar;
    } break;
    default:
        vhttp_configurator_errprintf(cmd, node, "argument must be scalar or mapping");
        return -1;
    }

    /* obtain uid & gid of the client that connects to the FastCGI daemon (i.e. vhttp after dropping privileges) */
    if (ctx->globalconf->user != NULL) {
        /* change ownership of temporary directory */
        if (getpwnam_r(ctx->globalconf->user, &vhttp_user_pwbuf, vhttp_user_buf, sizeof(vhttp_user_buf), &vhttp_user_pw) != 0 ||
            vhttp_user_pw == NULL) {
            vhttp_configurator_errprintf(cmd, node, "getpwnam_r(3) failed to obtain uid of user:%s", ctx->globalconf->user);
            goto Exit;
        }
    } else {
        vhttp_user_pw = NULL;
    }

    { /* build args */
        size_t i = 0;
        argv[i++] = kill_on_close_cmd_path = vhttp_configurator_get_cmd_path("share/vhttp/kill-on-close");
        argv[i++] = "--rm";
        argv[i++] = dirname;
        argv[i++] = "--";
        if (spawn_user != NULL) {
            argv[i++] = setuidgid_cmd_path = vhttp_configurator_get_cmd_path("share/vhttp/setuidgid");
            argv[i++] = spawn_user;
        }
        argv[i++] = "/bin/sh";
        argv[i++] = "-c";
        argv[i++] = spawn_cmd;
        argv[i++] = NULL;
        assert(i <= sizeof(argv) / sizeof(argv[0]));
    }

    if (ctx->dry_run) {
        dirname[0] = '\0';
        spawner_fd = -1;
        sa.sun_family = AF_UNIX;
        strcpy(sa.sun_path, "/dry-run.nonexistent");
    } else {
        /* create temporary directory */
        if (mkdtemp(dirname) == NULL) {
            vhttp_configurator_errprintf(cmd, node, "mkdtemp(3) failed to create temporary directory:%s:%s", dirname,
                                       strerror(errno));
            dirname[0] = '\0';
            goto Exit;
        }
        /* change ownership of temporary directory */
        if (vhttp_user_pw != NULL && chown(dirname, vhttp_user_pw->pw_uid, vhttp_user_pw->pw_gid) != 0) {
            vhttp_configurator_errprintf(cmd, node, "chown(2) failed to change ownership of temporary directory:%s:%s", dirname,
                                       strerror(errno));
            goto Exit;
        }
        /* launch spawnfcgi command */
        if ((spawner_fd = create_spawnproc(cmd, node, dirname, argv, &sa, vhttp_user_pw)) == -1) {
            goto Exit;
        }
    }

    config_vars = *self->vars;
    config_vars.callbacks.dispose = spawnproc_on_dispose;
    config_vars.callbacks.data = (char *)NULL + spawner_fd;

    vhttp_url_t upstream;
    vhttp_url_init_with_sun_path(&upstream, NULL, &vhttp_URL_SCHEME_FASTCGI, vhttp_iovec_init(sa.sun_path, strlen(sa.sun_path)),
                               vhttp_iovec_init(vhttp_STRLIT("/")));
    vhttp_fastcgi_register(ctx->pathconf, &upstream, &config_vars);
    free(upstream.authority.base);

    ret = 0;
Exit:
    if (dirname[0] != '\0')
        unlink(dirname);
    free(kill_on_close_cmd_path);
    free(setuidgid_cmd_path);
    return ret;
}

static int on_config_enter(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct fastcgi_configurator_t *self = (void *)_self;

    --self->vars;
    return 0;
}

void vhttp_fastcgi_register_configurator(vhttp_globalconf_t *conf)
{
    struct fastcgi_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->io_timeout = vhttp_DEFAULT_FASTCGI_IO_TIMEOUT;
    c->vars->keepalive_timeout = 0;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    vhttp_configurator_define_command(&c->super, "fastcgi.connect",
                                    vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_EXTENSION | vhttp_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_connect);
    vhttp_configurator_define_command(&c->super, "fastcgi.spawn",
                                    vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_EXTENSION | vhttp_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_spawn);
    vhttp_configurator_define_command(&c->super, "fastcgi.timeout.io",
                                    vhttp_CONFIGURATOR_FLAG_ALL_LEVELS | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_timeout_io);
    vhttp_configurator_define_command(&c->super, "fastcgi.timeout.keepalive",
                                    vhttp_CONFIGURATOR_FLAG_ALL_LEVELS | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_timeout_keepalive);
    vhttp_configurator_define_command(&c->super, "fastcgi.document_root",
                                    vhttp_CONFIGURATOR_FLAG_ALL_LEVELS | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_document_root);
    vhttp_configurator_define_command(&c->super, "fastcgi.send-delegated-uri",
                                    vhttp_CONFIGURATOR_FLAG_ALL_LEVELS | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_send_delegated_uri);
}
