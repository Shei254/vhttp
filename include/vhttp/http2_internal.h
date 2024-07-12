/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd.
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
#ifndef vhttp__http2__internal_h
#define vhttp__http2__internal_h

#include <assert.h>
#include <stdint.h>
#include "khash.h"
#include "vhttp/cache.h"
#include "vhttp/http2_casper.h"
#include "vhttp/http2_scheduler.h"

typedef struct st_vhttp_http2_conn_t vhttp_http2_conn_t;
typedef struct st_vhttp_http2_stream_t vhttp_http2_stream_t;

typedef enum enum_vhttp_http2_stream_state_t {
    /**
     * stream in idle state (but registered; i.e. priority stream)
     */
    vhttp_HTTP2_STREAM_STATE_IDLE,
    /**
     * receiving headers
     */
    vhttp_HTTP2_STREAM_STATE_RECV_HEADERS,
    /**
     * receiving body (or trailers), waiting for the arrival of END_STREAM
     */
    vhttp_HTTP2_STREAM_STATE_RECV_BODY,
    /**
     * received request but haven't been assigned a handler
     */
    vhttp_HTTP2_STREAM_STATE_REQ_PENDING,
    /**
     * waiting for receiving response headers from the handler
     */
    vhttp_HTTP2_STREAM_STATE_SEND_HEADERS,
    /**
     * sending body
     */
    vhttp_HTTP2_STREAM_STATE_SEND_BODY,
    /**
     * received EOS from handler but still is sending body to client
     */
    vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL,
    /**
     * closed
     */
    vhttp_HTTP2_STREAM_STATE_END_STREAM
} vhttp_http2_stream_state_t;

typedef struct st_vhttp_http2_conn_num_streams_t {
    uint32_t open;
    uint32_t half_closed;
    uint32_t send_body;
} vhttp_http2_conn_num_streams_t;

struct st_vhttp_http2_stream_t {
    /**
     * stream-id
     */
    uint32_t stream_id;
    /**
     * scheduler (entries below scheduler are not maintained after the stream is closed, see ...)
     */
    vhttp_http2_scheduler_openref_t _scheduler;
    /**
     * link-list of streams govered by connection.c
     */
    vhttp_linklist_t _link;
    /**
     * the final ostream
     */
    vhttp_ostream_t _ostr_final;
    vhttp_http2_stream_state_t state;
    vhttp_http2_window_t output_window;
    struct {
        vhttp_http2_window_t window;
        size_t bytes_unnotified;
    } input_window;
    vhttp_http2_priority_t received_priority;
    vhttp_VECTOR(vhttp_sendvec_t) _data;
    /**
     * points to http2_conn_t::num_streams::* in which the stream is counted
     */
    vhttp_http2_conn_num_streams_t *_num_streams_slot;
    vhttp_cache_digests_t *cache_digests;
    union {
        struct {
            uint32_t parent_stream_id;
            unsigned promise_sent : 1;
        } push;
        struct {
            unsigned casper_is_ready : 1;
        } pull;
    };
    unsigned blocked_by_server : 1;
    unsigned reset_by_peer : 1;
    /**
     *  state of the ostream, only used in push mode
     */
    vhttp_send_state_t send_state;
    /**
     * request body (not available when `buf` is NULL
     */
    struct {
        vhttp_buffer_t *buf;
        enum en_vhttp_req_body_state_t {
            vhttp_HTTP2_REQ_BODY_NONE,
            vhttp_HTTP2_REQ_BODY_OPEN_BEFORE_FIRST_FRAME,
            vhttp_HTTP2_REQ_BODY_OPEN,
            vhttp_HTTP2_REQ_BODY_CLOSE_QUEUED,
            vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED
        } state;
        /**
         * if the response body is streaming or was streamed, including tunnels
         */
        unsigned streamed : 1;
    } req_body;
    /**
     * the request object; placed at last since it is large and has it's own ctor
     */
    vhttp_req_t req;
};

KHASH_MAP_INIT_INT64(vhttp_http2_stream_t, vhttp_http2_stream_t *)

typedef enum enum_vhttp_http2_conn_state_t {
    vhttp_HTTP2_CONN_STATE_OPEN,        /* accepting new connections */
    vhttp_HTTP2_CONN_STATE_HALF_CLOSED, /* no more accepting new streams */
    vhttp_HTTP2_CONN_STATE_IS_CLOSING   /* nothing should be sent */
} vhttp_http2_conn_state_t;

struct st_vhttp_http2_conn_t {
    vhttp_conn_t super;
    vhttp_socket_t *sock;
    /* settings */
    vhttp_http2_settings_t peer_settings;
    /* streams */
    khash_t(vhttp_http2_stream_t) * streams;
    struct {
        uint32_t max_open;
        uint32_t max_processed;
    } pull_stream_ids;
    struct {
        uint32_t max_open;
    } push_stream_ids;
    struct {
        vhttp_http2_conn_num_streams_t priority;
        vhttp_http2_conn_num_streams_t pull;
        vhttp_http2_conn_num_streams_t push;
        uint32_t blocked_by_server;
        /**
         * number of streams that have the flag with the same name being set
         */
        uint32_t _req_streaming_in_progress;
        /**
         * number of CONNECT tunnels inflight (this is a proper subset of `_req_streaming_in_progress`)
         */
        uint32_t tunnel;
    } num_streams;
    /* internal */
    vhttp_http2_scheduler_node_t scheduler;
    vhttp_http2_conn_state_t state;
    unsigned is_chromium_dependency_tree : 1; /* indicates whether the client-generated dependency tree is from Chromium. The
                                               * denpendency tree of Chromium satisfies the following properties:
                                               * 1) Every stream has the exclusive bit set
                                               * 2) On a dependency tree, child's weight is lower than or equal to parent's
                                               */
    unsigned received_any_request : 1; /* if any request has been received. The connection is not subject to culling until at least
                                        * one request has been processed. */

    ssize_t (*_read_expect)(vhttp_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
    vhttp_buffer_t *_http1_req_input; /* contains data referred to by original request via HTTP/1.1 */
    vhttp_hpack_header_table_t _input_header_table;
    vhttp_http2_window_t _input_window;
    vhttp_hpack_header_table_t _output_header_table;
    vhttp_linklist_t _pending_reqs; /* list of vhttp_http2_stream_t that contain pending requests */
    vhttp_timer_t _timeout_entry;
    vhttp_buffer_t *_headers_unparsed; /* for temporary storing HEADERS|CONTINUATION frames without END_HEADERS flag set */
    struct {
        vhttp_buffer_t *buf;
        vhttp_buffer_t *buf_in_flight;
        vhttp_linklist_t streams_to_proceed;
        vhttp_timer_t timeout_entry;
        vhttp_http2_window_t window;
    } _write;
    vhttp_cache_t *push_memo;
    vhttp_http2_casper_t *casper;
    struct {
        vhttp_linklist_t blocked_streams;
    } early_data;
    vhttp_iovec_t *http2_origin_frame;
    /**
     * Ring buffer of closed streams. `next_slot` points to the next write position. The stored object is shrinked to only contain
     * stream_id and _scheduler.
     */
    struct {
#define HTTP2_CLOSED_STREAM_PRIORITIES 10
        vhttp_http2_stream_t *streams[HTTP2_CLOSED_STREAM_PRIORITIES];
        size_t next_slot;
    } _recently_closed_streams;
    struct {
        struct timeval settings_sent_at;
        struct timeval settings_acked_at;
    } timestamps;
    /**
     * timeout entry used for graceful shutdown
     */
    vhttp_timer_t _graceful_shutdown_timeout;
    /**
     * DoS mitigation; the idea here is to delay processing requests when observing suspicious behavior
     */
    struct {
        vhttp_timer_t process_delay;
        size_t reset_budget; /* RST_STREAM frames are considered suspicious when this value goes down to zero */
    } dos_mitigation;
};

/* connection */
void vhttp_http2_conn_register_stream(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
void vhttp_http2_conn_unregister_stream(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
static vhttp_http2_stream_t *vhttp_http2_conn_get_stream(vhttp_http2_conn_t *conn, uint32_t stream_id);
void vhttp_http2_conn_push_path(vhttp_http2_conn_t *conn, vhttp_iovec_t path, vhttp_http2_stream_t *src_stream);
void vhttp_http2_conn_request_write(vhttp_http2_conn_t *conn);
void vhttp_http2_conn_register_for_proceed_callback(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
static ssize_t vhttp_http2_conn_get_buffer_window(vhttp_http2_conn_t *conn);
static void vhttp_http2_conn_init_casper(vhttp_http2_conn_t *conn, unsigned capacity_bits);
void vhttp_http2_conn_register_for_replay(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
void vhttp_http2_conn_preserve_stream_scheduler(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *src);

/* stream */
static int vhttp_http2_stream_is_push(uint32_t stream_id);
vhttp_http2_stream_t *vhttp_http2_stream_open(vhttp_http2_conn_t *conn, uint32_t stream_id, vhttp_req_t *src_req,
                                          const vhttp_http2_priority_t *received_priority);
static void vhttp_http2_stream_update_open_slot(vhttp_http2_stream_t *stream, vhttp_http2_conn_num_streams_t *slot);
static void vhttp_http2_stream_set_blocked_by_server(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, unsigned on);
static void vhttp_http2_stream_set_state(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, vhttp_http2_stream_state_t new_state);
static void vhttp_http2_stream_prepare_for_request(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
void vhttp_http2_stream_close(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
void vhttp_http2_stream_reset(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
void vhttp_http2_stream_send_pending_data(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
static int vhttp_http2_stream_has_pending_data(vhttp_http2_stream_t *stream);
void vhttp_http2_stream_proceed(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
static void vhttp_http2_stream_send_push_promise(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream);
vhttp_http2_debug_state_t *vhttp_http2_get_debug_state(vhttp_req_t *req, int hpack_enabled);

/* inline definitions */

inline vhttp_http2_stream_t *vhttp_http2_conn_get_stream(vhttp_http2_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(vhttp_http2_stream_t, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return kh_val(conn->streams, iter);
    return NULL;
}

inline int vhttp_http2_stream_is_push(uint32_t stream_id)
{
    return stream_id % 2 == 0;
}

inline ssize_t vhttp_http2_conn_get_buffer_window(vhttp_http2_conn_t *conn)
{
    ssize_t ret, winsz;
    size_t capacity, cwnd_left;

    capacity = conn->_write.buf->capacity;
    if ((cwnd_left = vhttp_socket_prepare_for_latency_optimized_write(
             conn->sock, &conn->super.ctx->globalconf->http2.latency_optimization)) < capacity) {
        capacity = cwnd_left;
        if (capacity < conn->_write.buf->size)
            return 0;
    }

    ret = capacity - conn->_write.buf->size;
    if (ret < vhttp_HTTP2_FRAME_HEADER_SIZE)
        return 0;
    ret -= vhttp_HTTP2_FRAME_HEADER_SIZE;
    winsz = vhttp_http2_window_get_avail(&conn->_write.window);
    if (winsz < ret)
        ret = winsz;
    return ret;
}

inline void vhttp_http2_conn_init_casper(vhttp_http2_conn_t *conn, unsigned capacity_bits)
{
    assert(conn->casper == NULL);
    conn->casper = vhttp_http2_casper_create(capacity_bits, 6);
}

inline void vhttp_http2_stream_update_open_slot(vhttp_http2_stream_t *stream, vhttp_http2_conn_num_streams_t *slot)
{
    --stream->_num_streams_slot->open;
    ++slot->open;
    stream->_num_streams_slot = slot;
}

inline void vhttp_http2_stream_set_blocked_by_server(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, unsigned on)
{
    if (on) {
        assert(!stream->blocked_by_server);
        stream->blocked_by_server = 1;
        ++conn->num_streams.blocked_by_server;
    } else {
        assert(stream->blocked_by_server);
        stream->blocked_by_server = 0;
        --conn->num_streams.blocked_by_server;
    }
}

inline void vhttp_http2_stream_set_state(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, vhttp_http2_stream_state_t new_state)
{
    switch (new_state) {
    case vhttp_HTTP2_STREAM_STATE_IDLE:
        assert(!"FIXME");
        break;
    case vhttp_HTTP2_STREAM_STATE_RECV_HEADERS:
        assert(stream->state == vhttp_HTTP2_STREAM_STATE_IDLE);
        if (vhttp_http2_stream_is_push(stream->stream_id))
            vhttp_http2_stream_update_open_slot(stream, &conn->num_streams.push);
        else
            vhttp_http2_stream_update_open_slot(stream, &conn->num_streams.pull);
        stream->state = new_state;
        stream->req.timestamps.request_begin_at = vhttp_gettimeofday(conn->super.ctx->loop);
        break;
    case vhttp_HTTP2_STREAM_STATE_RECV_BODY:
        stream->state = new_state;
        stream->req.timestamps.request_body_begin_at = vhttp_gettimeofday(conn->super.ctx->loop);
        break;
    case vhttp_HTTP2_STREAM_STATE_REQ_PENDING:
        stream->state = new_state;
        break;
    case vhttp_HTTP2_STREAM_STATE_SEND_HEADERS:
        assert(stream->state == vhttp_HTTP2_STREAM_STATE_REQ_PENDING);
        ++stream->_num_streams_slot->half_closed;
        stream->state = new_state;
        break;
    case vhttp_HTTP2_STREAM_STATE_SEND_BODY:
        assert(stream->state == vhttp_HTTP2_STREAM_STATE_SEND_HEADERS);
        stream->state = new_state;
        ++stream->_num_streams_slot->send_body;
        break;
    case vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
        assert(stream->state == vhttp_HTTP2_STREAM_STATE_SEND_BODY);
        stream->state = new_state;
        break;
    case vhttp_HTTP2_STREAM_STATE_END_STREAM:
        switch (stream->state) {
        case vhttp_HTTP2_STREAM_STATE_IDLE:
        case vhttp_HTTP2_STREAM_STATE_RECV_BODY:
        case vhttp_HTTP2_STREAM_STATE_RECV_HEADERS:
            break;
        case vhttp_HTTP2_STREAM_STATE_REQ_PENDING:
            break;
        case vhttp_HTTP2_STREAM_STATE_SEND_HEADERS:
            --stream->_num_streams_slot->half_closed;
            break;
        case vhttp_HTTP2_STREAM_STATE_SEND_BODY:
        case vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
            --stream->_num_streams_slot->half_closed;
            --stream->_num_streams_slot->send_body;
            break;
        case vhttp_HTTP2_STREAM_STATE_END_STREAM:
            assert(!"FIXME");
            break;
        }
        stream->state = new_state;
        stream->req.timestamps.response_end_at = vhttp_gettimeofday(conn->super.ctx->loop);
        --stream->_num_streams_slot->open;
        stream->_num_streams_slot = NULL;
        if (stream->blocked_by_server)
            vhttp_http2_stream_set_blocked_by_server(conn, stream, 0);
        break;
    }

    /* Unless the connection is already in shutdown state, set the connection to ether IDLE or ACTIVE state depending on if there is
     * any request in flight. */
    if (!vhttp_timer_is_linked(&conn->_graceful_shutdown_timeout)) {
        size_t num_reqs_inflight = conn->num_streams.pull.open + conn->num_streams.pull.half_closed + conn->num_streams.push.open +
                                   conn->num_streams.push.half_closed;
        if (conn->received_any_request && num_reqs_inflight == 0) {
            vhttp_conn_set_state(&conn->super, vhttp_CONN_STATE_IDLE);
        } else {
            vhttp_conn_set_state(&conn->super, vhttp_CONN_STATE_ACTIVE);
        }
    }
}

inline void vhttp_http2_stream_prepare_for_request(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    assert(conn->state != vhttp_HTTP2_CONN_STATE_IS_CLOSING);
    assert(vhttp_http2_scheduler_is_open(&stream->_scheduler));

    /* adjust max-open */
    uint32_t *max_open = NULL;
    if (vhttp_http2_stream_is_push(stream->stream_id)) {
        max_open = &conn->push_stream_ids.max_open;
    } else if (conn->state == vhttp_HTTP2_CONN_STATE_OPEN) {
        max_open = &conn->pull_stream_ids.max_open;
    }
    if (max_open != NULL && *max_open < stream->stream_id)
        *max_open = stream->stream_id;

    vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_RECV_HEADERS);
    vhttp_http2_window_init(&stream->output_window, conn->peer_settings.initial_window_size);
}

inline int vhttp_http2_stream_has_pending_data(vhttp_http2_stream_t *stream)
{
    return stream->_data.size != 0;
}

inline void vhttp_http2_stream_send_push_promise(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    assert(!stream->push.promise_sent);
    vhttp_hpack_flatten_push_promise(&conn->_write.buf, &conn->_output_header_table, conn->peer_settings.header_table_size,
                                   stream->stream_id, conn->peer_settings.max_frame_size, stream->req.input.scheme,
                                   stream->req.input.authority, stream->req.input.method, stream->req.input.path,
                                   stream->req.headers.entries, stream->req.headers.size, stream->push.parent_stream_id);
    stream->push.promise_sent = 1;
}

#endif
