/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
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

struct st_vhttp_uv_socket_t {
    vhttp_socket_t super;
    uv_handle_t *handle;
    uv_close_cb close_cb;
    vhttp_timer_t write_cb_timer;
    union {
        struct {
            union {
                uv_connect_t _creq;
                uv_write_t _wreq;
            };
        } stream;
        struct {
            int events;
        } poll;
    };
};

static void do_ssl_write(struct st_vhttp_uv_socket_t *sock, int is_first_call, vhttp_iovec_t *initial_bufs, size_t initial_bufcnt);

static void alloc_inbuf(vhttp_buffer_t **buf, uv_buf_t *_vec)
{
    vhttp_iovec_t vec = vhttp_buffer_try_reserve(buf, 4096);

    /* Returning {NULL, 0} upon reservation failure is fine. Quoting from http://docs.libuv.org/en/v1.x/handle.html#c.uv_alloc_cb,
     * "if NULL is assigned as the buffer’s base or 0 as its length, a UV_ENOBUFS error will be triggered in the uv_udp_recv_cb or
     * the uv_read_cb callback."
     */
    memcpy(_vec, &vec, sizeof(vec));
}

static void alloc_inbuf_tcp(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    struct st_vhttp_uv_socket_t *sock = handle->data;
    alloc_inbuf(&sock->super.input, buf);
}

static void alloc_inbuf_ssl(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    struct st_vhttp_uv_socket_t *sock = handle->data;
    alloc_inbuf(&sock->super.ssl->input.encrypted, buf);
}

static void on_read_tcp(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    struct st_vhttp_uv_socket_t *sock = stream->data;

    if (nread < 0) {
        sock->super._cb.read(&sock->super, vhttp_socket_error_closed);
        return;
    }

    sock->super.input->size += nread;
    sock->super.bytes_read += nread;
    sock->super._cb.read(&sock->super, NULL);
}

static void on_read_ssl(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    struct st_vhttp_uv_socket_t *sock = stream->data;
    size_t prev_size = sock->super.input->size;
    const char *err = vhttp_socket_error_io;

    if (nread > 0) {
        sock->super.ssl->input.encrypted->size += nread;
        if (sock->super.ssl->handshake.cb == NULL)
            err = decode_ssl_input(&sock->super);
        else
            err = NULL;
    }
    sock->super.bytes_read += sock->super.input->size - prev_size;
    sock->super._cb.read(&sock->super, err);
}

static void on_poll(uv_poll_t *poll, int status, int events);
static void update_poll(struct st_vhttp_uv_socket_t *sock)
{
    assert(sock->handle->type == UV_POLL);
    if (sock->poll.events == 0) {
        uv_poll_stop((uv_poll_t *)sock->handle);
    } else {
        uv_poll_start((uv_poll_t *)sock->handle, sock->poll.events, on_poll);
    }
}

static void on_poll(uv_poll_t *poll, int status, int events)
{
    struct st_vhttp_uv_socket_t *sock = poll->data;
    const char *err = status == 0 ? NULL : vhttp_socket_error_io;

    if ((events & UV_READABLE) != 0) {
        sock->super._cb.read(&sock->super, err);
    }
    if ((events & UV_WRITABLE) != 0) {
        sock->super._cb.write(&sock->super, err);
        sock->poll.events &= ~UV_WRITABLE;
        update_poll(sock);
    }
}

static void on_do_write_complete(uv_write_t *wreq, int status)
{
    struct st_vhttp_uv_socket_t *sock = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_uv_socket_t, stream._wreq, wreq);

    dispose_write_buf(&sock->super);

    if (sock->super._cb.write != NULL)
        on_write_complete(&sock->super, status == 0 ? NULL : vhttp_socket_error_io);
}

static void free_sock(uv_handle_t *handle)
{
    struct st_vhttp_uv_socket_t *sock = handle->data;
    uv_close_cb cb = sock->close_cb;
    free(sock);
    cb(handle);
}

void do_dispose_socket(vhttp_socket_t *_sock)
{
    struct st_vhttp_uv_socket_t *sock = (struct st_vhttp_uv_socket_t *)_sock;
    sock->super._cb.write = NULL; /* avoid the write callback getting called when closing the socket (#1249) */
    vhttp_timer_unlink(&sock->write_cb_timer);
    uv_close(sock->handle, free_sock);
}

int vhttp_socket_get_fd(vhttp_socket_t *_sock)
{
    int fd, ret;
    struct st_vhttp_uv_socket_t *sock = (struct st_vhttp_uv_socket_t *)_sock;

    ret = uv_fileno(sock->handle, (uv_os_fd_t *)&fd);
    if (ret)
        return -1;

    return fd;
}

void do_read_start(vhttp_socket_t *_sock)
{
    struct st_vhttp_uv_socket_t *sock = (struct st_vhttp_uv_socket_t *)_sock;

    switch (sock->handle->type) {
    case UV_TCP:
        if (sock->super.ssl == NULL) {
            uv_read_start((uv_stream_t *)sock->handle, alloc_inbuf_tcp, on_read_tcp);
        } else {
            uv_read_start((uv_stream_t *)sock->handle, alloc_inbuf_ssl, on_read_ssl);
        }
        break;
    case UV_POLL:
        sock->poll.events |= UV_READABLE;
        uv_poll_start((uv_poll_t *)sock->handle, sock->poll.events, on_poll);
        break;
    default:
        vhttp_fatal("unexpected handle type");
    }
}

void do_read_stop(vhttp_socket_t *_sock)
{
    struct st_vhttp_uv_socket_t *sock = (struct st_vhttp_uv_socket_t *)_sock;

    switch (sock->handle->type) {
    case UV_TCP:
        uv_read_stop((uv_stream_t *)sock->handle);
        break;
    case UV_POLL:
        sock->poll.events &= ~UV_READABLE;
        update_poll(sock);
        break;
    default:
        vhttp_fatal("unexpected handle type");
    }
}

static void on_call_write_success(vhttp_timer_t *timer)
{
    struct st_vhttp_uv_socket_t *sock = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_uv_socket_t, write_cb_timer, timer);
    on_do_write_complete(&sock->stream._wreq, 0);
}

static void on_call_write_error(vhttp_timer_t *timer)
{
    struct st_vhttp_uv_socket_t *sock = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_uv_socket_t, write_cb_timer, timer);
    on_do_write_complete(&sock->stream._wreq, 1);
}

static void call_write_complete_delayed(struct st_vhttp_uv_socket_t *sock, int status)
{
    sock->write_cb_timer.cb = status == 0 ? on_call_write_success : on_call_write_error;
    vhttp_timer_link(sock->handle->loop, 0, &sock->write_cb_timer);
}

void report_early_write_error(vhttp_socket_t *_sock)
{
    struct st_vhttp_uv_socket_t *sock = (struct st_vhttp_uv_socket_t *)_sock;
    call_write_complete_delayed(sock, 1);
}

static void on_ssl_write_complete(uv_write_t *wreq, int status)
{
    struct st_vhttp_uv_socket_t *sock = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_uv_socket_t, stream._wreq, wreq);

    assert(has_pending_ssl_bytes(sock->super.ssl));
    dispose_ssl_output_buffer(sock->super.ssl);

    /* If current write succeeded and there's more to be sent, call `do_ssl_write`. Otherwise, the operation is complete. */
    if (status == 0 && sock->super._write_buf.cnt != 0) {
        do_ssl_write(sock, 0, NULL, 0);
    } else {
        on_do_write_complete(&sock->stream._wreq, status);
    }
}

void do_ssl_write(struct st_vhttp_uv_socket_t *sock, int is_first_call, vhttp_iovec_t *initial_bufs, size_t initial_bufcnt)
{
    vhttp_iovec_t **bufs;
    size_t *bufcnt;

    if (is_first_call) {
        bufs = &initial_bufs;
        bufcnt = &initial_bufcnt;
    } else {
        bufs = &sock->super._write_buf.bufs;
        bufcnt = &sock->super._write_buf.cnt;
    }

    /* generate TLS records */
    size_t first_buf_written = 0;
    if (!has_pending_ssl_bytes(sock->super.ssl) &&
        (first_buf_written = generate_tls_records(&sock->super, bufs, bufcnt, 0)) == SIZE_MAX) {
        if (is_first_call) {
            call_write_complete_delayed(sock, 1);
        } else {
            on_do_write_complete(&sock->stream._wreq, 1);
        }
    }

    if (*bufcnt == 0) {
        /* Bail out if nothing has to be sent */
        if (!has_pending_ssl_bytes(sock->super.ssl)) {
            if (is_first_call) {
                call_write_complete_delayed(sock, 0);
            } else {
                on_do_write_complete(&sock->stream._wreq, 0);
            }
            return;
        }
    } else {
        /* There's more cleartext data to be converted and to be sent. Record pending cleartext data. */
        assert(has_pending_ssl_bytes(sock->super.ssl));
        if (is_first_call) {
            init_write_buf(&sock->super, *bufs, *bufcnt, first_buf_written);
        } else {
            sock->super._write_buf.bufs->base += first_buf_written;
            sock->super._write_buf.bufs->len -= first_buf_written;
        }
    }

    /* Send pending TLS records. */
    uv_buf_t uvbuf = {(char *)sock->super.ssl->output.buf.base, sock->super.ssl->output.buf.off};
    uv_write(&sock->stream._wreq, (uv_stream_t *)sock->handle, &uvbuf, 1, on_ssl_write_complete);
}

void do_write(vhttp_socket_t *_sock, vhttp_iovec_t *bufs, size_t bufcnt)
{
    struct st_vhttp_uv_socket_t *sock = (struct st_vhttp_uv_socket_t *)_sock;
    assert(sock->handle->type == UV_TCP);

    if (sock->super.ssl == NULL) {
        if (bufcnt > 0) {
            uv_write(&sock->stream._wreq, (uv_stream_t *)sock->handle, (uv_buf_t *)bufs, (int)bufcnt, on_do_write_complete);
        } else {
            call_write_complete_delayed(sock, 0);
        }
    } else {
        do_ssl_write(sock, 1, bufs, bufcnt);
    }
}

void vhttp_socket_notify_write(vhttp_socket_t *_sock, vhttp_socket_cb cb)
{
    struct st_vhttp_uv_socket_t *sock = (struct st_vhttp_uv_socket_t *)_sock;
    assert(sock->handle->type == UV_POLL);
    assert(sock->super._cb.write == NULL);

    sock->super._cb.write = cb;
    sock->poll.events |= UV_WRITABLE;
    uv_poll_start((uv_poll_t *)sock->handle, sock->poll.events, on_poll);
}

static struct st_vhttp_uv_socket_t *create_socket(vhttp_loop_t *loop)
{
    uv_tcp_t *tcp = vhttp_mem_alloc(sizeof(*tcp));

    if (uv_tcp_init(loop, tcp) != 0) {
        free(tcp);
        return NULL;
    }
    return (void *)vhttp_uv_socket_create((void *)tcp, (uv_close_cb)free);
}

int do_export(vhttp_socket_t *_sock, vhttp_socket_export_t *info)
{
    struct st_vhttp_uv_socket_t *sock = (void *)_sock;
    assert(sock->handle->type == UV_TCP);
    uv_os_fd_t fd;

    if (uv_fileno(sock->handle, &fd) != 0)
        return -1;
    /* FIXME: consider how to overcome the epoll(2) problem; man says,
     * "even after a file descriptor that is part of an epoll set has been closed,
     * events may be reported for that file descriptor if other file descriptors
     * referring to the same underlying file description remain open"
     */
    if ((info->fd = dup(fd)) == -1)
        return -1;
    return 0;
}

vhttp_socket_t *do_import(vhttp_loop_t *loop, vhttp_socket_export_t *info)
{
    struct st_vhttp_uv_socket_t *sock = create_socket(loop);

    if (sock == NULL)
        return NULL;
    if (uv_tcp_open((uv_tcp_t *)sock->handle, info->fd) != 0) {
        vhttp_socket_close(&sock->super);
        return NULL;
    }

    return &sock->super;
}

vhttp_socket_t *vhttp_uv__poll_create(vhttp_loop_t *loop, int fd, uv_close_cb close_cb)
{
    uv_poll_t *poll = vhttp_mem_alloc(sizeof(*poll));
    if (uv_poll_init(loop, poll, fd) != 0) {
        free(poll);
        return NULL;
    }
    return vhttp_uv_socket_create((uv_handle_t *)poll, close_cb);
}

vhttp_socket_t *vhttp_uv_socket_create(uv_handle_t *handle, uv_close_cb close_cb)
{
    struct st_vhttp_uv_socket_t *sock = vhttp_mem_alloc(sizeof(*sock));
    memset(sock, 0, sizeof(*sock));
    vhttp_buffer_init(&sock->super.input, &vhttp_socket_buffer_prototype);

    sock->handle = handle;
    sock->close_cb = close_cb;
    sock->handle->data = sock;
    vhttp_timer_init(&sock->write_cb_timer, on_call_write_success);
    uint64_t flags = vhttp_socket_ebpf_lookup_flags(sock->handle->loop, vhttp_socket_ebpf_init_key, &sock->super);
    if ((flags & vhttp_EBPF_FLAGS_SKIP_TRACING_BIT) != 0)
        sock->super._skip_tracing = 1;
    return &sock->super;
}

static void on_connect(uv_connect_t *conn, int status)
{
    if (status == UV_ECANCELED)
        return;
    struct st_vhttp_uv_socket_t *sock = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_uv_socket_t, stream._creq, conn);
    vhttp_socket_cb cb = sock->super._cb.write;
    sock->super._cb.write = NULL;
    cb(&sock->super, status == 0 ? NULL : vhttp_socket_error_conn_fail);
}

vhttp_loop_t *vhttp_socket_get_loop(vhttp_socket_t *_sock)
{
    struct st_vhttp_uv_socket_t *sock = (void *)_sock;
    return sock->handle->loop;
}

vhttp_socket_t *vhttp_socket_connect(vhttp_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, vhttp_socket_cb cb, const char **err)
{
    struct st_vhttp_uv_socket_t *sock = create_socket(loop);

    if (sock == NULL) {
        if (err != NULL)
            *err = vhttp_socket_error_socket_fail;
        return NULL;
    }
    if (uv_tcp_connect(&sock->stream._creq, (void *)sock->handle, addr, on_connect) != 0) {
        vhttp_socket_close(&sock->super);
        if (err != NULL)
            *err = vhttp_socket_error_socket_fail;
        return NULL;
    }
    sock->super._cb.write = cb;
    return &sock->super;
}

socklen_t get_sockname_uncached(vhttp_socket_t *_sock, struct sockaddr *sa)
{
    struct st_vhttp_uv_socket_t *sock = (void *)_sock;
    assert(sock->handle->type == UV_TCP);

    int len = sizeof(struct sockaddr_storage);
    if (uv_tcp_getsockname((void *)sock->handle, sa, &len) != 0)
        return 0;
    return (socklen_t)len;
}

socklen_t get_peername_uncached(vhttp_socket_t *_sock, struct sockaddr *sa)
{
    struct st_vhttp_uv_socket_t *sock = (void *)_sock;
    assert(sock->handle->type == UV_TCP);

    int len = sizeof(struct sockaddr_storage);
    if (uv_tcp_getpeername((void *)sock->handle, sa, &len) != 0)
        return 0;
    return (socklen_t)len;
}

static void on_timeout(uv_timer_t *uv_timer)
{
    vhttp_timer_t *timer = uv_timer->data;
    timer->is_linked = 0;
    timer->cb(timer);
}

void vhttp_timer_link(vhttp_loop_t *l, uint64_t delay_ticks, vhttp_timer_t *timer)
{
    if (timer->uv_timer == NULL) {
        timer->uv_timer = vhttp_mem_alloc(sizeof(*timer->uv_timer));
        uv_timer_init(l, timer->uv_timer);
        timer->uv_timer->data = timer;
    }
    timer->is_linked = 1;
    uv_timer_start(timer->uv_timer, on_timeout, delay_ticks, 0);
}

void vhttp_timer_unlink(vhttp_timer_t *timer)
{
    timer->is_linked = 0;
    if (timer->uv_timer != NULL) {
        uv_timer_stop(timer->uv_timer);
        uv_close((uv_handle_t *)timer->uv_timer, (uv_close_cb)free);
        timer->uv_timer = NULL;
    }
}
