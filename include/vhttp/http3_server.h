/*
 * Copyright (c) 2018 Fastly, Kazuho
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
#ifndef vhttp__http3_server_h
#define vhttp__http3_server_h

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include "quicly.h"
#include "vhttp/http3_common.h"
#include "vhttp.h"

typedef struct st_vhttp_http3_server_ctx_t {
    vhttp_quic_ctx_t super;
    vhttp_accept_ctx_t *accept_ctx;
    unsigned send_retry : 1;
    vhttp_http3_qpack_context_t qpack;
} vhttp_http3_server_ctx_t;

extern const vhttp_http3_conn_callbacks_t vhttp_HTTP3_CONN_CALLBACKS;

/**
 * initializes the context
 */
void vhttp_http3_server_init_context(vhttp_context_t *vhttp, vhttp_quic_ctx_t *ctx, vhttp_loop_t *loop, vhttp_socket_t *sock,
                                   quicly_context_t *quic, quicly_cid_plaintext_t *next_cid, vhttp_quic_accept_cb acceptor,
                                   vhttp_quic_notify_connection_update_cb notify_conn_update, uint8_t use_gso);

/**
 * the acceptor callback to be used together with vhttp_http3_server_ctx_t
 * @return a pointer to a new connection object upon success, NULL or vhttp_QUIC_ACCEPT_CONN_DECRYPTION_FAILED upon failure.
 */
vhttp_http3_conn_t *vhttp_http3_server_accept(vhttp_http3_server_ctx_t *ctx, quicly_address_t *destaddr, quicly_address_t *srcaddr,
                                          quicly_decoded_packet_t *packet, quicly_address_token_plaintext_t *address_token,
                                          int skip_tracing, const vhttp_http3_conn_callbacks_t *h3_callbacks);
/**
 * amends the quicly context so that it could be used for the server
 */
void vhttp_http3_server_amend_quicly_context(vhttp_globalconf_t *conf, quicly_context_t *quic);
/**
 * Given a QUIC connection context, returns the application-level connection context. Caller must not supply QUIC connections used
 * for other purposes than serving HTTP response (e.g., that created by http3client).
 */
vhttp_conn_t *vhttp_http3_get_connection(quicly_conn_t *quic);

#ifdef __cplusplus
}
#endif

#endif
