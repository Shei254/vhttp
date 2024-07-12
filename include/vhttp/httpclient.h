/*
 * Copyright (c) 2017 Ichito Nagata, Fastly, Inc.
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
#ifndef vhttp__httpclient_h
#define vhttp__httpclient_h

#ifdef __cplusplus
extern "C" {
#endif

#include "quicly.h"
#include "vhttp/header.h"
#include "vhttp/hostinfo.h"
#include "vhttp/http3_common.h"
#include "vhttp/send_state.h"
#include "vhttp/socket.h"
#include "vhttp/socketpool.h"

typedef struct st_vhttp_httpclient_t vhttp_httpclient_t;

typedef void (*vhttp_httpclient_forward_datagram_cb)(vhttp_httpclient_t *client, vhttp_iovec_t *datagrams, size_t num_datagrams);

/**
 * Additional properties related to the HTTP request being issued.
 * When the connect callback is being called, the properties of the objects are set to their initial values. Applications MAY alter
 * the properties to achieve desirable behavior. The reason we require the protocol stacks to initialize the values to their default
 * values instead of requiring applications to set all the values correctly is to avoid requiring applications making changes
 * every time a new field is added to the object.
 */
typedef struct st_vhttp_httpclient_properties_t {
    /**
     * When the value is a non-NULL pointer (at the moment, only happens with the HTTP/1 client), the application MAY set it to an
     * iovec pointing to the payload of the PROXY protocol (i.e., the first line).
     */
    vhttp_iovec_t *proxy_protocol;
    /**
     * When the value is a non-NULL pointer (at the moment, only happens with the HTTP/1 client), the application MAY set it to 1 to
     * indicate that the request body should be encoded using the chunked transfer-encoding.
     */
    int *chunked;
    /**
     * When the value is a non-NULL pointer (at the moment, only happens with the HTTP/1 client), the application MAY set it to the
     * value of the connection header field to be sent to the server. This value is advisory in sense that 1) the server might
     * decide to close the connection even if the client sent `keep-alive` and 2) the field may be rewritten to `upgrade` if the
     * client requested upgrade (extended CONNECT).
     */
    vhttp_iovec_t *connection_header;
    /**
     * defaults to false
     */
    unsigned prefer_pipe_reader : 1;
    /**
     * When the value is 1, httpclient sends 'expect: 100-continue' header and suspends sending request body
     * until it sees 100-continue response
     */
    unsigned use_expect : 1;
} vhttp_httpclient_properties_t;

typedef struct st_vhttp_httpclient_pipe_reader_t vhttp_httpclient_pipe_reader_t;

typedef struct st_vhttp_httpclient_on_head_t {
    int version;
    int status;
    vhttp_iovec_t msg;
    vhttp_header_t *headers;
    size_t num_headers;
    int header_requires_dup;
    struct {
        vhttp_httpclient_forward_datagram_cb write_, *read_;
    } forward_datagram;
    /**
     * If this pointer is set to non-NULL by the HTTP client, it is offering the user the opportunity to read content to a pipe,
     * rather than suppliend them as bytes. To take that opportunity, users should set the members of the pointed struct to
     * appropriate values. Note that even when the user opts in to using a pipe, first chunk of content may still be served through
     * memory, as the content would be read into memory alongside the HTTP response headers.
     */
    vhttp_httpclient_pipe_reader_t *pipe_reader;
} vhttp_httpclient_on_head_t;

typedef void (*vhttp_httpclient_proceed_req_cb)(vhttp_httpclient_t *client, const char *errstr);
typedef int (*vhttp_httpclient_body_cb)(vhttp_httpclient_t *client, const char *errstr, vhttp_header_t *trailers, size_t num_trailers);
typedef vhttp_httpclient_body_cb (*vhttp_httpclient_head_cb)(vhttp_httpclient_t *client, const char *errstr,
                                                         vhttp_httpclient_on_head_t *args);
/**
 * Called when the protocol stack is ready to issue a request. Application must set all the output parameters (i.e. all except
 * `client`, `errstr`, `origin`) and return a callback that will be called when the protocol stack receives the response headers
 * from the server.
 */
typedef vhttp_httpclient_head_cb (*vhttp_httpclient_connect_cb)(vhttp_httpclient_t *client, const char *errstr, vhttp_iovec_t *method,
                                                            vhttp_url_t *url, const vhttp_header_t **headers, size_t *num_headers,
                                                            vhttp_iovec_t *body, vhttp_httpclient_proceed_req_cb *proceed_req_cb,
                                                            vhttp_httpclient_properties_t *props, vhttp_url_t *origin);
typedef int (*vhttp_httpclient_informational_cb)(vhttp_httpclient_t *client, int version, int status, vhttp_iovec_t msg,
                                               vhttp_header_t *headers, size_t num_headers);

typedef void (*vhttp_httpclient_finish_cb)(vhttp_httpclient_t *client);

struct st_vhttp_httpclient_pipe_reader_t {
    int fd;
    vhttp_httpclient_body_cb on_body_piped;
};

typedef struct st_vhttp_httpclient_connection_pool_t {
    /**
     * used to establish connections and pool those when h1 is used.
     * socketpool is shared among multiple threads while connection pool is dedicated to each thread
     */
    vhttp_socketpool_t *socketpool;

    struct {
        vhttp_linklist_t conns;
    } http2;

    struct {
        vhttp_linklist_t conns;
    } http3;

} vhttp_httpclient_connection_pool_t;

typedef struct st_vhttp_httpclient_protocol_ratio_t {
    /**
     * If non-negative, indicates the percentage of requests for which use of HTTP/2 will be attempted. If set to negative, all
     * connections are established with ALPN offering both H1 and H2, then the load is balanced between the different protocol
     * versions. This behavior helps balance the load among a mixture of servers behind a load balancer, some supporting both H1 and
     * H2 and some supporting only H1.
     */
    int8_t http2;
    /**
     * Indicates the percentage of requests for which HTTP/3 should be used. Unlike HTTP/2, this value cannot be negative, because
     * unlike ALPN over TLS over TCP, the choice of the protocol is up to the client.
     */
    int8_t http3;
} vhttp_httpclient_protocol_ratio_t;

typedef struct st_vhttp_http3client_ctx_t vhttp_http3client_ctx_t;

typedef struct st_vhttp_httpclient_ctx_t {
    vhttp_loop_t *loop;
    vhttp_multithread_receiver_t *getaddr_receiver;
    uint64_t io_timeout;
    uint64_t connect_timeout;
    uint64_t first_byte_timeout;
    uint64_t keepalive_timeout; /* only used for http2 for now */
    size_t max_buffer_size;
    unsigned tunnel_enabled : 1;
    unsigned force_cleartext_http2 : 1;

    struct st_vhttp_httpclient_protocol_selector_t {
        vhttp_httpclient_protocol_ratio_t ratio;
        /**
         * Each deficit is initialized to zero, then incremented by the respective percentage, and the protocol corresponding to the
         * one with the highest value is chosen. Then, the chosen variable is decremented by 100.
         */
        int16_t _deficits[4];
    } protocol_selector;

    /**
     * HTTP/2-specific settings
     */
    struct {
        vhttp_socket_latency_optimization_conditions_t latency_optimization;
        uint32_t max_concurrent_streams;
    } http2;

    /**
     * HTTP/3-specific settings; 1-to(0|1) relationship, NULL when h3 is not used
     */
    vhttp_http3client_ctx_t *http3;

} vhttp_httpclient_ctx_t;

struct st_vhttp_http3client_ctx_t {
    ptls_context_t tls;
    quicly_context_t quic;
    vhttp_quic_ctx_t h3;
    uint64_t max_frame_payload_size;
    /**
     * Optional callback invoked by the HTTP/3 client implementation to obtain information used for resuming a connection. When the
     * connection is to be resumed, the callback should set `*address_token` and `*session_ticket` to a vector that can be freed by
     * calling free (3), as well as writing the resumed transport parameters to `*resumed_tp`. Otherwise, `*address_token`,
     * `*session_ticket`, `*resumed_tp` can be left untouched, and a full handshake will be exercised. The function returns if the
     * operation was successful. When false is returned, the connection attempt is aborted.
     */
    int (*load_session)(vhttp_httpclient_ctx_t *ctx, struct sockaddr *server_addr, const char *server_name,
                        ptls_iovec_t *address_token, ptls_iovec_t *session_ticket, quicly_transport_parameters_t *resumed_tp);
};

typedef struct st_vhttp_httpclient_timings_t {
    struct timeval start_at;
    struct timeval request_begin_at;
    struct timeval request_end_at;
    struct timeval response_start_at;
    struct timeval response_end_at;
} vhttp_httpclient_timings_t;

/**
 * Properties of a HTTP client connection.
 */
typedef struct st_vhttp_httpclient_conn_properties_t {
    /**
     * TLS properties. Definitions match that returned by corresponding vhttp_socket function: `vhttp_socket_ssl_*`.
     */
    struct {
        const char *protocol_version;
        int session_reused;
        const char *cipher;
        int cipher_bits;
    } ssl;
    /**
     * Underlying TCP connection, if any.
     */
    vhttp_socket_t *sock;
} vhttp_httpclient_conn_properties_t;

struct st_vhttp_httpclient_t {
    /**
     * memory pool
     */
    vhttp_mem_pool_t *pool;
    /**
     * context
     */
    vhttp_httpclient_ctx_t *ctx;
    /**
     * connection pool
     */
    vhttp_httpclient_connection_pool_t *connpool;
    /**
     * buffer in which response data is stored (see update_window)
     */
    vhttp_buffer_t **buf;
    /**
     * application data pointer
     */
    void *data;
    /**
     * optional callback to receive informational response(s); 101 is considered final and is never delivered through this callback
     */
    vhttp_httpclient_informational_cb informational_cb;
    /**
     * server-timing data
     */
    vhttp_httpclient_timings_t timings;
    /**
     * If the stream is to be converted to convey some other protocol, this value should be set to the name of the protocol, which
     * will be indicated by the `upgrade` request header field. Additionally, intent to create a CONNECT tunnel is indicated by a
     * special label called `vhttp_httpclient_upgrade_to_connect`.
     */
    const char *upgrade_to;

    /**
     * bytes written (above the TLS layer)
     */
    struct {
        uint64_t header;
        uint64_t body;
        uint64_t total;
    } bytes_written;

    /**
     * bytes read (above the TLS layer)
     */
    struct {
        uint64_t header;
        uint64_t body;
        uint64_t total;
    } bytes_read;

    /**
     * cancels a in-flight request
     */
    void (*cancel)(vhttp_httpclient_t *client);
    /**
     * returns a pointer to the underlying vhttp_socket_t
     */
    void (*get_conn_properties)(vhttp_httpclient_t *client, vhttp_httpclient_conn_properties_t *properties);
    /**
     * callback that should be called when some data is fetched out from `buf`.
     */
    void (*update_window)(vhttp_httpclient_t *client);
    /**
     * Function for writing request body. `proceed_req_cb` supplied through the `on_connect` callback will be called when the
     * given data is sent to the server. Regarding the usage, refer to the doc-comment of `vhttp_write_req_cb`.
     */
    int (*write_req)(vhttp_httpclient_t *client, vhttp_iovec_t chunk, int is_end_stream);

    vhttp_timer_t _timeout;
    vhttp_socketpool_connect_request_t *_connect_req;
    union {
        vhttp_httpclient_connect_cb on_connect;
        vhttp_httpclient_head_cb on_head;
        vhttp_httpclient_body_cb on_body;
    } _cb;
};

/**
 * public members of h2 client connection
 */
typedef struct st_vhttp_httpclient__h2_conn_t {
    /**
     * context
     */
    vhttp_httpclient_ctx_t *ctx;
    /**
     * origin server (path is ignored)
     */
    vhttp_url_t origin_url;
    /**
     * underlying socket
     */
    vhttp_socket_t *sock;
    /**
     * number of open streams (FIXME can't we refer to khash?)
     */
    size_t num_streams;
    /**
     * linklist of connections anchored to vhttp_httpclient_connection_pool_t::http2.conns. The link is in the ascending order of
     * `num_streams`.
     */
    vhttp_linklist_t link;
} vhttp_httpclient__h2_conn_t;

struct st_vhttp_httpclient__h3_conn_t {
    vhttp_http3_conn_t super;
    vhttp_httpclient_ctx_t *ctx;
    /**
     * When the socket is associated to a global pool, used to identify the origin. If not associated to a global pool, the values
     * are zero-filled.
     */
    struct {
        /**
         * the origin URL; null-termination of authority and host is guaranteed
         */
        vhttp_url_t origin_url;
        /**
         * port number in C string
         */
        char named_serv[sizeof(vhttp_UINT16_LONGEST_STR)];
    } server;
    ptls_handshake_properties_t handshake_properties;
    vhttp_timer_t timeout;
    vhttp_hostinfo_getaddr_req_t *getaddr_req;
    /**
     * linked to vhttp_httpclient_ctx_t::http3.conns
     */
    vhttp_linklist_t link;
    /**
     * linklist used to queue pending requests
     */
    vhttp_linklist_t pending_requests;
};

extern const char vhttp_httpclient_error_is_eos[];
extern const char vhttp_httpclient_error_refused_stream[];
extern const char vhttp_httpclient_error_unknown_alpn_protocol[];
extern const char vhttp_httpclient_error_io[];
extern const char vhttp_httpclient_error_connect_timeout[];
extern const char vhttp_httpclient_error_first_byte_timeout[];
extern const char vhttp_httpclient_error_io_timeout[];
extern const char vhttp_httpclient_error_invalid_content_length[];
extern const char vhttp_httpclient_error_flow_control[];
extern const char vhttp_httpclient_error_http1_line_folding[];
extern const char vhttp_httpclient_error_http1_unexpected_transfer_encoding[];
extern const char vhttp_httpclient_error_http1_parse_failed[];
extern const char vhttp_httpclient_error_protocol_violation[];
extern const char vhttp_httpclient_error_internal[];
extern const char vhttp_httpclient_error_malformed_frame[];
extern const char vhttp_httpclient_error_unexpected_101[];


extern const char vhttp_httpclient_upgrade_to_connect[];

void vhttp_httpclient_connection_pool_init(vhttp_httpclient_connection_pool_t *connpool, vhttp_socketpool_t *sockpool);

/**
 * issues a HTTP request using the connection pool. Either H1 or H2 may be used, depending on the given context.
 * TODO: create H1- or H2-specific connect function that works without the connection pool?
 */
void vhttp_httpclient_connect(vhttp_httpclient_t **client, vhttp_mem_pool_t *pool, void *data, vhttp_httpclient_ctx_t *ctx,
                            vhttp_httpclient_connection_pool_t *connpool, vhttp_url_t *target, const char *upgrade_to,
                            vhttp_httpclient_connect_cb on_connect);

void vhttp_httpclient__h1_on_connect(vhttp_httpclient_t *client, vhttp_socket_t *sock, vhttp_url_t *origin);
extern const size_t vhttp_httpclient__h1_size;

void vhttp_httpclient__h2_on_connect(vhttp_httpclient_t *client, vhttp_socket_t *sock, vhttp_url_t *origin);
uint32_t vhttp_httpclient__h2_get_max_concurrent_streams(vhttp_httpclient__h2_conn_t *conn);
extern const size_t vhttp_httpclient__h2_size;

void vhttp_httpclient_set_conn_properties_of_socket(vhttp_socket_t *sock, vhttp_httpclient_conn_properties_t *properties);

#ifdef quicly_h /* create http3client.h? */

#include "vhttp/http3_common.h"

void vhttp_httpclient_http3_notify_connection_update(vhttp_quic_ctx_t *ctx, vhttp_quic_conn_t *conn);
extern quicly_stream_open_t vhttp_httpclient_http3_on_stream_open;
extern quicly_receive_datagram_frame_t vhttp_httpclient_http3_on_receive_datagram_frame;
void vhttp_httpclient__connect_h3(vhttp_httpclient_t **client, vhttp_mem_pool_t *pool, void *data, vhttp_httpclient_ctx_t *ctx,
                                vhttp_httpclient_connection_pool_t *connpool, vhttp_url_t *target, const char *upgrade_to,
                                vhttp_httpclient_connect_cb cb);
/**
 * internal API for checking if the stream is to be turned into a tunnel
 */
static int vhttp_httpclient__tunnel_is_ready(vhttp_httpclient_t *client, int status, int http_version);

/* inline definitions */

inline int vhttp_httpclient__tunnel_is_ready(vhttp_httpclient_t *client, int status, int http_version)
{
    if (client->upgrade_to != NULL) {
        if (client->upgrade_to == vhttp_httpclient_upgrade_to_connect && 200 <= status && status <= 299)
            return 1;
        if (http_version < 0x200) {
            if (status == 101)
                return 1;
        } else {
            if (200 <= status && status <= 299)
                return 1;
        }
    }
    return 0;
}

#endif

#ifdef __cplusplus
}
#endif

#endif
