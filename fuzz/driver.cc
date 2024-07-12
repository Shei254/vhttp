/*
 * Copyright (c) 2016 Fastly, Inc.
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

/*
 * This file implements a test harness for using vhttp with LibFuzzer.
 * See http://llvm.org/docs/LibFuzzer.html for more info.
 */

#define vhttp_USE_EPOLL 1
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include "vhttp.h"
#include "vhttp/http1.h"
#include "vhttp/http2.h"
#include "vhttp/url.h"
#include "vhttp/memcached.h"

#include "driver_common.h"

#if !defined(HTTP1) && !defined(HTTP2)
#error "Please defined one of HTTP1 or HTTP2"
#endif

#if defined(HTTP1) && defined(HTTP2)
#error "Please defined one of HTTP1 or HTTP2, but not both"
#endif

static vhttp_globalconf_t config;
static vhttp_context_t ctx;
static vhttp_accept_ctx_t accept_ctx;
static int client_timeout_ms;
static char unix_listener[PATH_MAX];

/*
 * Request handler used for testing. Returns a basic "200 OK" response.
 */
static int chunked_test(vhttp_handler_t *self, vhttp_req_t *req)
{
    static vhttp_generator_t generator = {NULL, NULL};

    if (!vhttp_memis(req->method.base, req->method.len, vhttp_STRLIT("GET")))
        return -1;

    vhttp_iovec_t body = vhttp_strdup(&req->pool, "hello world\n", SIZE_MAX);
    req->res.status = 200;
    req->res.reason = "OK";
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CONTENT_TYPE, NULL, vhttp_STRLIT("text/plain"));
    vhttp_start_response(req, &generator);
    vhttp_send(req, &body, 1, vhttp_SEND_STATE_FINAL);

    return 0;
}

/* copy from src to dst, return true if src has EOF */
static int drain(int fd)
{
    char buf[4096];
    ssize_t n;

    n = read(fd, buf, sizeof(buf));
    if (n <= 0) {
        return 1;
    }
    return 0;
}

/* A request sent from client thread to vhttp server */
struct writer_thread_arg {
    char *buf;
    size_t len;
    int fd;
    vhttp_barrier_t barrier;
};

/*
 * Reads writer_thread_arg from fd and stores to buf
 */
static void read_fully(int fd, char *buf, size_t len)
{
    int done = 0;
    while (len) {
        int ret;
        while ((ret = read(fd, buf + done, len)) == -1 && errno == EINTR)
            ;
        if (ret <= 0) {
            abort();
        }
        done += ret;
        len -= ret;
    }
}

/*
 * Thread: Loops writing fuzzed req to socket and then reading results back.
 * Acts as a client to vhttp. *arg points to file descripter to read
 * writer_thread_args from.
 */
void *writer_thread(void *arg)
{
    int rfd = (long)arg;
    while (1) {
        int pos, sockinp, sockoutp, cnt, len;
        char *buf;
        struct writer_thread_arg *wta;

        /* Get fuzzed request */
        read_fully(rfd, (char *)&wta, sizeof(wta));

        pos = 0;
        sockinp = wta->fd;
        sockoutp = wta->fd;
        cnt = 0;
        buf = wta->buf;
        len = wta->len;

        /*
         * Send fuzzed req and read results until the socket is closed (or
         * something spurious happens)
         */
        while (cnt++ < 20 && (pos < len || sockinp >= 0)) {
#define MARKER "\n--MARK--\n"
            /* send 1 packet */
            if (pos < len) {
                char *p = (char *)memmem(buf + pos, len - pos, MARKER, sizeof(MARKER) - 1);
                if (p) {
                    int l = p - (buf + pos);
                    write(sockoutp, buf + pos, l);
                    pos += l;
                    pos += sizeof(MARKER) - 1;
                }
            } else {
                if (sockinp >= 0) {
                    shutdown(sockinp, SHUT_WR);
                }
            }

            /* drain socket */
            if (sockinp >= 0) {
                struct timeval timeo;
                fd_set rd;
                int n;

                FD_ZERO(&rd);
                FD_SET(sockinp, &rd);
                timeo.tv_sec = 0;
                timeo.tv_usec = client_timeout_ms * 1000;
                n = select(sockinp + 1, &rd, NULL, NULL, &timeo);
                if (n > 0 && FD_ISSET(sockinp, &rd) && drain(sockinp)) {
                    sockinp = -1;
                }
            }
        }
        close(wta->fd);
        vhttp_barrier_wait(&wta->barrier);
        vhttp_barrier_dispose(&wta->barrier);
        free(wta);
    }
}

/*
 * Creates socket pair and passes fuzzed req to a thread (the HTTP[/2] client)
 * for writing to the target vhttp server. Returns the server socket fd.
 */
static int feeder(int sfd, char *buf, size_t len, vhttp_barrier_t **barrier)
{
    int pair[2];
    struct writer_thread_arg *wta;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
        return -1;

    wta = (struct writer_thread_arg *)malloc(sizeof(*wta));
    wta->fd = pair[0];
    wta->buf = buf;
    wta->len = len;
    vhttp_barrier_init(&wta->barrier, 2);
    *barrier = &wta->barrier;

    write_fully(sfd, (char *)&wta, sizeof(wta), 1);
    return pair[1];
}

/*
 * Creates/connects socket pair for client/server interaction and passes
 * fuzzed request to client for sending.
 * Returns server socket fd.
 */
static int create_accepted(int sfd, char *buf, size_t len, vhttp_barrier_t **barrier)
{
    int fd;
    vhttp_socket_t *sock;
    struct timeval connected_at = vhttp_gettimeofday(ctx.loop);

    /* Create an HTTP[/2] client that will send the fuzzed request */
    fd = feeder(sfd, buf, len, barrier);
    if (fd < 0) {
        abort();
    }

    /* Pass the server socket to vhttp and invoke request processing */
    sock = vhttp_evloop_socket_create(ctx.loop, fd, vhttp_SOCKET_FLAG_IS_ACCEPTED_CONNECTION);

#if defined(HTTP1)
    vhttp_http1_accept(&accept_ctx, sock, connected_at);
#else
    vhttp_http2_accept(&accept_ctx, sock, connected_at);
#endif

    return fd;
}

/*
 * Returns true if fd if valid. Used to determine when connection is closed.
 */
static int is_valid_fd(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

/*
 * Entry point for libfuzzer.
 * See http://llvm.org/docs/LibFuzzer.html for more info
 */
static int init_done;
static int job_queue[2];
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    int c;
    vhttp_loop_t *loop;
    vhttp_hostconf_t *hostconf;
    pthread_t twriter;
    pthread_t tupstream;

    /*
     * Perform one-time initialization
     */
    if (!init_done) {
        const char *client_timeout_ms_str;
        static char tmpname[] = "/tmp/vhttp-fuzz-XXXXXX";
        char *dirname;

        vhttp_barrier_init(&init_barrier, 2);
        signal(SIGPIPE, SIG_IGN);

        dirname = mkdtemp(tmpname);
        snprintf(unix_listener, sizeof(unix_listener), "http://[unix://%s/_.sock]/proxy", dirname);
        if ((client_timeout_ms_str = getenv("vhttp_FUZZER_CLIENT_TIMEOUT")) != NULL)
            client_timeout_ms = atoi(client_timeout_ms_str);
        if (!client_timeout_ms)
            client_timeout_ms = 10;

        /* Create a single vhttp host with multiple request handlers */
        vhttp_config_init(&config);
        config.http2.idle_timeout = 10 * 1000;
        config.http1.req_timeout = 10 * 1000;
        hostconf = vhttp_config_register_host(&config, vhttp_iovec_init(vhttp_STRLIT(unix_listener)), 65535);
        register_handler(hostconf, "/chunked-test", chunked_test);
        register_proxy(hostconf, unix_listener, NULL);
        vhttp_file_register(vhttp_config_register_path(hostconf, "/", 0), "./examples/doc_root", NULL, NULL, 0);

        loop = vhttp_evloop_create();
        vhttp_context_init(&ctx, loop, &config);

        accept_ctx.ctx = &ctx;
        accept_ctx.hosts = config.hosts;

        /* Create a thread to act as the HTTP client */
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, job_queue) != 0) {
            abort();
        }
        if (pthread_create(&twriter, NULL, writer_thread, (void *)(long)job_queue[1]) != 0) {
            abort();
        }
        if (pthread_create(&tupstream, NULL, upstream_thread, dirname) != 0) {
            abort();
        }
        vhttp_barrier_wait(&init_barrier);
        init_done = 1;
    }

    /*
     * Pass fuzzed request to client thread and get vhttp server socket for
     * use below
     */
    vhttp_barrier_t *end;
    c = create_accepted(job_queue[0], (char *)Data, (size_t)Size, &end);
    if (c < 0) {
        goto Error;
    }

    /* Loop until the connection is closed by the client or server */
    while (is_valid_fd(c)) {
        vhttp_evloop_run(ctx.loop, client_timeout_ms);
    }

    vhttp_barrier_wait(end);
    return 0;
Error:
    return 1;
}
