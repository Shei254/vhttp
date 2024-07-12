/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#ifndef vhttp__websocket_h
#define vhttp__websocket_h

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>
#include "vhttp.h"
#include "vhttp/http1.h"

typedef struct st_vhttp_websocket_conn_t vhttp_websocket_conn_t;

/* if arg is NULL, the user should close connection by calling vhttp_websocket_close() */
typedef void (*vhttp_websocket_msg_callback)(vhttp_websocket_conn_t *conn, const struct wslay_event_on_msg_recv_arg *arg);

struct st_vhttp_websocket_conn_t {
    vhttp_socket_t *sock;
    wslay_event_context_ptr ws_ctx;
    struct wslay_event_callbacks ws_callbacks;
    void *data;
    vhttp_websocket_msg_callback cb;
    struct {
        size_t cnt;
        vhttp_iovec_t bufs[4];
    } _write_buf;
};

int vhttp_is_websocket_handshake(vhttp_req_t *req, const char **client_key);
vhttp_websocket_conn_t *vhttp_upgrade_to_websocket(vhttp_req_t *req, const char *client_key, void *user_data,
                                               vhttp_websocket_msg_callback msg_cb);
void vhttp_websocket_close(vhttp_websocket_conn_t *conn);
void vhttp_websocket_proceed(vhttp_websocket_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif
