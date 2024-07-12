/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "vhttp.h"
#include "vhttp/serverutil.h"

struct st_vhttp_access_log_filehandle_t {
    vhttp_logconf_t *logconf;
    int fd;
};

struct st_vhttp_access_logger_t {
    vhttp_logger_t super;
    vhttp_access_log_filehandle_t *fh;
};

static void log_access(vhttp_logger_t *_self, vhttp_req_t *req)
{
    struct st_vhttp_access_logger_t *self = (struct st_vhttp_access_logger_t *)_self;
    vhttp_access_log_filehandle_t *fh = self->fh;
    char *logline, buf[4096];
    size_t len;

    /* stringify */
    len = sizeof(buf);
    logline = vhttp_log_request(fh->logconf, req, &len, buf);

    /* emit */
    write(fh->fd, logline, len);

    /* free memory */
    if (logline != buf)
        free(logline);
}

static void on_dispose_handle(void *_fh)
{
    vhttp_access_log_filehandle_t *fh = _fh;

    vhttp_logconf_dispose(fh->logconf);
    close(fh->fd);
}

int vhttp_access_log_open_log(const char *path)
{
    int fd;

    if (path[0] == '|') {
        int pipefds[2];
        pid_t pid;
        char *argv[4] = {"/bin/sh", "-c", (char *)(path + 1), NULL};
        /* create pipe */
        if (pipe(pipefds) != 0) {
            vhttp_perror("pipe failed");
            return -1;
        }
        if (fcntl(pipefds[1], F_SETFD, FD_CLOEXEC) == -1) {
            vhttp_perror("failed to set FD_CLOEXEC on pipefds[1]");
            return -1;
        }
        /* spawn the logger */
        int mapped_fds[] = {pipefds[0], 0, /* map pipefds[0] to stdin */
                            -1};
        if ((pid = vhttp_spawnp(argv[0], argv, mapped_fds, 0)) == -1) {
            vhttp_error_printf("failed to open logger: %s:%s\n", path + 1, strerror(errno));
            return -1;
        }
        /* close the read side of the pipefds and return the write side */
        close(pipefds[0]);
        fd = pipefds[1];
    } else {
        struct stat st;
        int ret;

        ret = stat(path, &st);
        if (ret == 0 && (st.st_mode & S_IFMT) == S_IFSOCK) {
            struct sockaddr_un sa;
            if (strlen(path) >= sizeof(sa.sun_path)) {
                vhttp_error_printf("path:%s is too long as a unix socket name", path);
                return -1;
            }
            if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
                vhttp_error_printf("failed to create socket for log file:%s:%s\n", path, strerror(errno));
                return -1;
            }
            memset(&sa, 0, sizeof(sa));
            sa.sun_family = AF_UNIX;
            strcpy(sa.sun_path, path);
            if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
                vhttp_error_printf("failed to connect socket for log file:%s:%s\n", path, strerror(errno));
                close(fd);
                return -1;
            }

        } else {
            if ((fd = open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644)) == -1) {
                vhttp_error_printf("failed to open log file:%s:%s\n", path, strerror(errno));
                return -1;
            }
        }
    }

    return fd;
}

vhttp_access_log_filehandle_t *vhttp_access_log_open_handle(const char *path, const char *fmt, int escape)
{
    vhttp_logconf_t *logconf;
    int fd;
    vhttp_access_log_filehandle_t *fh;
    char errbuf[256];

    /* default to combined log format */
    if (fmt == NULL)
        fmt = "%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\"";
    if ((logconf = vhttp_logconf_compile(fmt, escape, errbuf)) == NULL) {
        vhttp_error_printf("%s\n", errbuf);
        return NULL;
    }

    /* open log file */
    if ((fd = vhttp_access_log_open_log(path)) == -1) {
        vhttp_logconf_dispose(logconf);
        return NULL;
    }

    fh = vhttp_mem_alloc_shared(NULL, sizeof(*fh), on_dispose_handle);
    fh->logconf = logconf;
    fh->fd = fd;
    return fh;
}

static void dispose(vhttp_logger_t *_self)
{
    struct st_vhttp_access_logger_t *self = (void *)_self;

    vhttp_mem_release_shared(self->fh);
}

vhttp_logger_t *vhttp_access_log_register(vhttp_pathconf_t *pathconf, vhttp_access_log_filehandle_t *fh)
{
    struct st_vhttp_access_logger_t *self = (void *)vhttp_create_logger(pathconf, sizeof(*self));

    self->super.dispose = dispose;
    self->super.log_access = log_access;
    self->fh = fh;
    vhttp_mem_addref_shared(fh);

    return &self->super;
}
