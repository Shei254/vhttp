/*
 * Copyright (c) 2018 Ichito Nagata, Fastly, Inc.
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
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "khash.h"
#include "vhttp/hpack.h"
#include "vhttp/httpclient.h"
#include "vhttp/http2_common.h"

#define vhttp_HTTP2_SETTINGS_CLIENT_CONNECTION_WINDOW_SIZE 16777216
#define vhttp_HTTP2_SETTINGS_CLIENT_HEADER_TABLE_SIZE 4096
#define vhttp_HTTP2_SETTINGS_CLIENT_MAX_FRAME_SIZE 16384

enum enum_vhttp_http2client_stream_state {
    STREAM_STATE_HEAD,
    STREAM_STATE_BODY,
    STREAM_STATE_CLOSED,
};

enum enum_vhttp_http2client_conn_state {
    vhttp_HTTP2CLIENT_CONN_STATE_OPEN,
    vhttp_HTTP2CLIENT_CONN_STATE_HALF_CLOSED,
    vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING,
};

struct st_vhttp_http2client_stream_t;
KHASH_MAP_INIT_INT64(stream, struct st_vhttp_http2client_stream_t *)

struct st_vhttp_http2client_conn_t {
    vhttp_httpclient__h2_conn_t super;
    enum enum_vhttp_http2client_conn_state state;
    khash_t(stream) * streams;
    vhttp_http2_settings_t peer_settings;
    uint32_t max_open_stream_id;
    vhttp_timer_t io_timeout;
    vhttp_timer_t keepalive_timeout;

    struct {
        vhttp_hpack_header_table_t header_table;
        vhttp_http2_window_t window;
        vhttp_buffer_t *buf;
        vhttp_buffer_t *buf_in_flight;
        vhttp_timer_t defer_timeout;
        vhttp_linklist_t sending_streams;
        vhttp_linklist_t sent_streams;
    } output;

    struct {
        vhttp_hpack_header_table_t header_table;
        vhttp_http2_window_t window;
        ssize_t (*read_frame)(struct st_vhttp_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
        vhttp_buffer_t *headers_unparsed;
    } input;
    vhttp_mem_pool_t rst_streams_pool;
};

struct st_vhttp_http2client_stream_t {
    vhttp_httpclient_t super;
    struct st_vhttp_http2client_conn_t *conn;
    uint32_t stream_id;
    struct {
        enum enum_vhttp_http2client_stream_state req;
        enum enum_vhttp_http2client_stream_state res;
    } state;

    struct {
        vhttp_http2_window_t window;
        vhttp_buffer_t *buf;
        vhttp_linklist_t sending_link;
        vhttp_httpclient_proceed_req_cb proceed_req; /* set to NULL once entire request body is provided to http2client */
    } output;

    struct {
        vhttp_http2_window_t window;
        int status;
        vhttp_headers_t headers;
        vhttp_buffer_t *body;
        vhttp_headers_t trailers;
        size_t remaining_content_length;
        unsigned message_body_forbidden : 1;
    } input;

    int *notify_destroyed;
};

static void do_emit_writereq(struct st_vhttp_http2client_conn_t *conn);

static void request_write(struct st_vhttp_http2client_conn_t *conn)
{
    if (conn->state == vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING)
        return;
    if (!vhttp_socket_is_writing(conn->super.sock) && !vhttp_timer_is_linked(&conn->output.defer_timeout))
        vhttp_timer_link(conn->super.ctx->loop, 0, &conn->output.defer_timeout);
}

static void enqueue_window_update(struct st_vhttp_http2client_conn_t *conn, uint32_t stream_id, vhttp_http2_window_t *window,
                                  size_t desired)
{
    assert(desired <= INT32_MAX);
    if (vhttp_http2_window_get_avail(window) * 2 < desired) {
        int32_t delta = (int32_t)(desired - vhttp_http2_window_get_avail(window));
        vhttp_http2_encode_window_update_frame(&conn->output.buf, stream_id, delta);
        request_write(conn);
        vhttp_http2_window_update(window, delta);
    }
}

static void stream_send_error(struct st_vhttp_http2client_conn_t *conn, uint32_t stream_id, int errnum)
{
    assert(stream_id != 0);
    assert(conn->state != vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING);

    vhttp_http2_encode_rst_stream_frame(&conn->output.buf, stream_id, -errnum);
    request_write(conn);
}

static struct st_vhttp_http2client_stream_t *get_stream(struct st_vhttp_http2client_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(stream, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return (struct st_vhttp_http2client_stream_t *)kh_val(conn->streams, iter);
    return NULL;
}

static uint32_t get_max_buffer_size(vhttp_httpclient_ctx_t *ctx)
{
    size_t sz = ctx->max_buffer_size;
    if (sz > INT32_MAX)
        sz = INT32_MAX;
    return (uint32_t)sz;
}

uint32_t vhttp_httpclient__h2_get_max_concurrent_streams(vhttp_httpclient__h2_conn_t *_conn)
{
    struct st_vhttp_http2client_conn_t *conn = (void *)_conn;
    return conn->peer_settings.max_concurrent_streams < conn->super.ctx->http2.max_concurrent_streams
               ? conn->peer_settings.max_concurrent_streams
               : conn->super.ctx->http2.max_concurrent_streams;
}

static void adjust_conn_linkedlist(vhttp_httpclient_connection_pool_t *connpool, struct st_vhttp_http2client_conn_t *conn, int forward)
{
    if (connpool == NULL) {
        assert(!vhttp_linklist_is_linked(&conn->super.link));
        return;
    }
    if (!vhttp_linklist_is_linked(&conn->super.link))
        return;

    double ratio = (double)conn->super.num_streams / vhttp_httpclient__h2_get_max_concurrent_streams(&conn->super);

    /* adjust connection linked list */
    vhttp_linklist_t *node = forward ? conn->super.link.next : conn->super.link.prev;
    while (node != &connpool->http2.conns) {
        struct st_vhttp_http2client_conn_t *cur = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http2client_conn_t, super.link, node);
        double cur_ratio = (double)cur->super.num_streams / vhttp_httpclient__h2_get_max_concurrent_streams(&cur->super);
        if (forward ? (ratio <= cur_ratio) : (ratio >= cur_ratio))
            break;
        node = forward ? node->next : node->prev;
    }
    if (forward) {
        if (node == conn->super.link.next)
            return;
    } else {
        if (node == conn->super.link.prev)
            return;
        if (node != &connpool->http2.conns)
            node = node->next; /* do `insert after` rather than `insert before` */
    }
    vhttp_linklist_unlink(&conn->super.link);
    vhttp_linklist_insert(node, &conn->super.link);
}

static void register_stream(struct st_vhttp_http2client_stream_t *stream, struct st_vhttp_http2client_conn_t *conn)
{
    assert(stream->stream_id == 0);

    stream->conn = conn;

    stream->stream_id = conn->max_open_stream_id == 0 ? 1 : conn->max_open_stream_id + 2;
    conn->max_open_stream_id = stream->stream_id;

    int r;
    khiter_t iter = kh_put(stream, conn->streams, stream->stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;

    ++conn->super.num_streams;

    if (vhttp_timer_is_linked(&conn->keepalive_timeout))
        vhttp_timer_unlink(&conn->keepalive_timeout);

    adjust_conn_linkedlist(stream->super.connpool, conn, 1);
}

static void unregister_stream(struct st_vhttp_http2client_stream_t *stream)
{
    khiter_t iter = kh_get(stream, stream->conn->streams, stream->stream_id);
    assert(iter != kh_end(stream->conn->streams));
    kh_del(stream, stream->conn->streams, iter);

    --stream->conn->super.num_streams;

    if (stream->conn->super.num_streams == 0)
        vhttp_timer_link(stream->conn->super.ctx->loop, stream->conn->super.ctx->keepalive_timeout, &stream->conn->keepalive_timeout);

    adjust_conn_linkedlist(stream->super.connpool, stream->conn, 0);
}

static void close_stream(struct st_vhttp_http2client_stream_t *stream)
{
    if (stream->conn != NULL) {
        unregister_stream(stream);
    }

    if (vhttp_timer_is_linked(&stream->super._timeout))
        vhttp_timer_unlink(&stream->super._timeout);
    if (vhttp_linklist_is_linked(&stream->output.sending_link))
        vhttp_linklist_unlink(&stream->output.sending_link);

    if (stream->output.buf != NULL)
        vhttp_buffer_dispose(&stream->output.buf);
    vhttp_buffer_dispose(&stream->input.body);

    if (stream->notify_destroyed != NULL)
        *stream->notify_destroyed = 1;

    free(stream);
}

static void close_response(struct st_vhttp_http2client_stream_t *stream)
{
    assert(stream->state.res != STREAM_STATE_CLOSED);
    stream->state.res = STREAM_STATE_CLOSED;
    if (stream->state.req == STREAM_STATE_CLOSED) {
        close_stream(stream);
    }
}

static void call_callback_with_error(struct st_vhttp_http2client_stream_t *stream, const char *errstr)
{
    assert(errstr != NULL);
    switch (stream->state.res) {
    case STREAM_STATE_HEAD: {
        vhttp_httpclient_on_head_t on_head = {.version = 0x200};
        stream->super._cb.on_head(&stream->super, errstr, &on_head);
    } break;
    case STREAM_STATE_BODY:
        stream->super._cb.on_body(&stream->super, errstr, NULL, 0);
        break;
    case STREAM_STATE_CLOSED:
        /* proceed_req can be called to indicate error, regardless of write being inflight */
        if (stream->output.proceed_req != NULL) {
            vhttp_httpclient_proceed_req_cb cb = stream->output.proceed_req;
            stream->output.proceed_req = NULL;
            cb(&stream->super, errstr);
        }
        break;
    }
}

static void call_stream_callbacks_with_error(struct st_vhttp_http2client_conn_t *conn, const char *errstr)
{
    struct st_vhttp_http2client_stream_t *stream;
    kh_foreach_value(conn->streams, stream, { call_callback_with_error(stream, errstr); });
}

static int extract_content_length(const vhttp_headers_t *headers, size_t *content_length, const char **err_desc)
{
    *content_length = SIZE_MAX;
    for (size_t i = 0; i < headers->size; ++i) {
        if (headers->entries[i].name == &vhttp_TOKEN_CONTENT_LENGTH->buf) {
            const vhttp_iovec_t *value = &headers->entries[i].value;
            if (*content_length != SIZE_MAX) {
                *err_desc = "duplicate content-length";
                return 0;
            }
            *content_length = vhttp_strtosize(value->base, value->len);
            if (*content_length == SIZE_MAX) {
                *err_desc = "malformed content-length";
                return 0;
            }
        }
    }
    return 1;
}

static int on_head(struct st_vhttp_http2client_conn_t *conn, struct st_vhttp_http2client_stream_t *stream, const uint8_t *src,
                   size_t len, const char **err_desc, int is_end_stream)
{
    int ret;
    vhttp_mem_pool_t *pool;
    int *status;
    vhttp_headers_t *headers;
    int dummy_status;
    vhttp_headers_t dummy_headers = {0};

    if (stream != NULL) {
        pool = stream->super.pool;
        status = &stream->input.status;
        headers = &stream->input.headers;
    } else {
        pool = &conn->rst_streams_pool;
        status = &dummy_status;
        headers = &dummy_headers;
    }

    if ((ret = vhttp_hpack_parse_response(pool, vhttp_hpack_decode_header, &conn->input.header_table, status, headers, NULL, src, len,
                                        err_desc)) != 0) {
        if (ret == vhttp_HTTP2_ERROR_INVALID_HEADER_CHAR) {
            ret = vhttp_HTTP2_ERROR_PROTOCOL;
            goto Failed;
        }
        return ret;
    }

    if (stream == NULL)
        return 0;

    if (100 <= stream->input.status && stream->input.status <= 199) {
        if (stream->input.status == 101) {
            ret = vhttp_HTTP2_ERROR_PROTOCOL; // TODO is this alright?
            goto Failed;
        }
        if (stream->super.informational_cb != NULL &&
            stream->super.informational_cb(&stream->super, 0, stream->input.status, vhttp_iovec_init(NULL, 0),
                                           stream->input.headers.entries, stream->input.headers.size) != 0) {
            ret = vhttp_HTTP2_ERROR_INTERNAL;
            goto SendRSTStream;
        }
        return 0;
    }

    if ((100 <= stream->input.status && stream->input.status <= 199) ||
        (stream->input.status == 204 || stream->input.status == 304)) {
        stream->input.message_body_forbidden = 1;
    }

    if (!extract_content_length(&stream->input.headers, &stream->input.remaining_content_length, err_desc)) {
        ret = vhttp_HTTP2_ERROR_PROTOCOL;
        goto Failed;
    }

    vhttp_httpclient_on_head_t on_head = {.version = 0x200,
                                        .status = stream->input.status,
                                        .msg = vhttp_iovec_init(NULL, 0),
                                        .headers = stream->input.headers.entries,
                                        .num_headers = stream->input.headers.size};
    stream->super._cb.on_body =
        stream->super._cb.on_head(&stream->super, is_end_stream ? vhttp_httpclient_error_is_eos : NULL, &on_head);

    if (is_end_stream) {
        close_response(stream);
        return 0;
    }
    if (stream->super._cb.on_body == NULL) {
        /**
         * NOTE: if on_head returns NULL due to invalid response (e.g. invalid content-length header)
         * sending RST_STREAM with PROTOCOL_ERROR might be more suitable than CANCEL
         * (see: https://tools.ietf.org/html/rfc7540#section-8.1.2.6)
         * but sending CANCEL is not wrong, so we leave this as-is for now.
         */
        ret = vhttp_HTTP2_ERROR_CANCEL;
        goto SendRSTStream;
    }

    stream->state.res = STREAM_STATE_BODY;

    return 0;

Failed:
    assert(ret == vhttp_HTTP2_ERROR_PROTOCOL);
    call_callback_with_error(stream, vhttp_httpclient_error_protocol_violation);
SendRSTStream:
    stream_send_error(conn, stream->stream_id, ret);
    close_stream(stream);
    return 0;
}

static int on_trailers(struct st_vhttp_http2client_conn_t *conn, struct st_vhttp_http2client_stream_t *stream, const uint8_t *src,
                       size_t len, const char **err_desc)
{
    int ret;

    assert(stream->state.res == STREAM_STATE_BODY);

    if ((ret = vhttp_hpack_parse_response(stream->super.pool, vhttp_hpack_decode_header, &conn->input.header_table, NULL,
                                        &stream->input.trailers, NULL, src, len, err_desc)) != 0) {
        if (ret == vhttp_HTTP2_ERROR_INVALID_HEADER_CHAR) {
            ret = vhttp_HTTP2_ERROR_PROTOCOL;
            goto Failed;
        }
        return ret;
    }

    if (stream->super._cb.on_body(&stream->super, vhttp_httpclient_error_is_eos, stream->input.trailers.entries,
                                  stream->input.trailers.size) != 0) {
        ret = vhttp_HTTP2_ERROR_INTERNAL;
        goto SendRSTStream;
    }
    close_response(stream);
    return 0;

Failed:
    assert(ret == vhttp_HTTP2_ERROR_PROTOCOL);
    call_callback_with_error(stream, vhttp_httpclient_error_protocol_violation);
SendRSTStream:
    stream_send_error(conn, stream->stream_id, ret);
    close_stream(stream);
    return 0;
}

ssize_t expect_default(struct st_vhttp_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
static ssize_t expect_continuation_of_headers(struct st_vhttp_http2client_conn_t *conn, const uint8_t *src, size_t len,
                                              const char **err_desc)
{
    vhttp_http2_frame_t frame;
    ssize_t ret;
    struct st_vhttp_http2client_stream_t *stream;
    int hret;

    if ((ret = vhttp_http2_decode_frame(&frame, src, len, vhttp_HTTP2_SETTINGS_CLIENT_MAX_FRAME_SIZE, err_desc)) < 0)
        return ret;
    if (frame.type != vhttp_HTTP2_FRAME_TYPE_CONTINUATION) {
        *err_desc = "expected CONTINUATION frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    stream = get_stream(conn, frame.stream_id);
    if (stream != NULL && stream->state.res == STREAM_STATE_CLOSED) {
        *err_desc = "unexpected stream id in CONTINUATION frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    vhttp_buffer_reserve(&conn->input.headers_unparsed, frame.length);
    memcpy(conn->input.headers_unparsed->bytes + conn->input.headers_unparsed->size, frame.payload, frame.length);
    conn->input.headers_unparsed->size += frame.length;

    if ((frame.flags & vhttp_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
        int is_end_stream = (frame.flags & vhttp_HTTP2_FRAME_FLAG_END_STREAM) != 0;
        conn->input.read_frame = expect_default;

        if (stream != NULL && stream->state.res == STREAM_STATE_BODY) {
            hret = on_trailers(conn, stream, (const uint8_t *)conn->input.headers_unparsed->bytes,
                               conn->input.headers_unparsed->size, err_desc);
        } else {
            hret = on_head(conn, stream, (const uint8_t *)conn->input.headers_unparsed->bytes, conn->input.headers_unparsed->size,
                           err_desc, is_end_stream);
        }
        if (hret != 0)
            ret = hret;

        vhttp_buffer_dispose(&conn->input.headers_unparsed);
        conn->input.headers_unparsed = NULL;
    }

    return ret;
}

static void do_update_window(vhttp_httpclient_t *client);
static int handle_data_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_data_payload_t payload;
    struct st_vhttp_http2client_stream_t *stream;
    int ret;

    if ((ret = vhttp_http2_decode_data_payload(&payload, frame, err_desc)) != 0)
        return ret;

    /* save the input in the request body buffer, or send error (and close the stream) */
    if ((stream = get_stream(conn, frame->stream_id)) == NULL) {
        if (frame->stream_id <= conn->max_open_stream_id) {
            vhttp_http2_window_consume_window(&conn->input.window, payload.length);
            enqueue_window_update(conn, 0, &conn->input.window, vhttp_HTTP2_SETTINGS_CLIENT_CONNECTION_WINDOW_SIZE);
            return 0;
        } else {
            *err_desc = "invalid DATA frame";
            return vhttp_HTTP2_ERROR_PROTOCOL;
        }
    }

    if (stream->state.res != STREAM_STATE_BODY) {
        stream_send_error(conn, frame->stream_id, vhttp_HTTP2_ERROR_PROTOCOL);
        call_callback_with_error(stream, vhttp_httpclient_error_protocol_violation);
        close_stream(stream);
        return 0;
    }

    /**
     * RFC7230 Section 3.3.
     *
     *  Responses to the HEAD request method (Section 4.3.2 of [RFC7231]) never
     *  include a message body because the associated response header fields
     *  (e.g., Transfer-Encoding, Content-Length, etc.), if present, indicate
     *  only what their values would have been if the request method had been
     *  GET (Section 4.3.1 of [RFC7231]).
     *
     *  2xx (Successful) responses to a CONNECT request method (Section 4.3.6
     *  of [RFC7231]) switch to tunnel mode instead of having a message body.
     *
     *  All 1xx (Informational), 204 (No Content), and 304 (Not Modified)
     *  responses do not include a message body.
     *
     *  All other responses do include a message body, although the body might
     *  be of zero length.
     */
    if (stream->input.message_body_forbidden && payload.length != 0) {
        stream_send_error(conn, frame->stream_id, vhttp_HTTP2_ERROR_PROTOCOL);
        call_callback_with_error(stream, vhttp_httpclient_error_protocol_violation);
        close_stream(stream);
        return 0;
    }

    /**
     * RFC 7540 Section 8.1.2.6.
     *  A request or response is also malformed if the value of
     *  a content-length header field does not equal the sum of the DATA frame
     *  payload lengths that form the body.
     */
    if (stream->input.remaining_content_length != SIZE_MAX) {
        if (payload.length > stream->input.remaining_content_length) {
            stream_send_error(conn, frame->stream_id, vhttp_HTTP2_ERROR_PROTOCOL);
            call_callback_with_error(stream, vhttp_httpclient_error_protocol_violation);
            close_stream(stream);
            return 0;
        }
        stream->input.remaining_content_length -= payload.length;
    }

    size_t max_size = get_max_buffer_size(stream->super.ctx);
    if (stream->input.body->size + payload.length > max_size) {
        call_callback_with_error(stream, vhttp_httpclient_error_flow_control);
        stream_send_error(stream->conn, stream->stream_id, vhttp_HTTP2_ERROR_FLOW_CONTROL);
        close_stream(stream);
        return 0;
    }

    vhttp_buffer_append(&stream->input.body, (void *)payload.data, payload.length);

    vhttp_http2_window_consume_window(&conn->input.window, payload.length);
    vhttp_http2_window_consume_window(&stream->input.window, payload.length);

    int is_final = (frame->flags & vhttp_HTTP2_FRAME_FLAG_END_STREAM) != 0;
    if (stream->super._cb.on_body(&stream->super, is_final ? vhttp_httpclient_error_is_eos : NULL, NULL, 0) != 0) {
        stream_send_error(conn, frame->stream_id, vhttp_HTTP2_ERROR_INTERNAL);
        close_stream(stream);
        return 0;
    }

    if (is_final) {
        close_response(stream);
    } else {
        /* update connection-level window */
        enqueue_window_update(stream->conn, 0, &stream->conn->input.window, vhttp_HTTP2_SETTINGS_CLIENT_CONNECTION_WINDOW_SIZE);
        /* update stream-level window */
        do_update_window(&stream->super);
    }

    return 0;
}

static int handle_headers_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_headers_payload_t payload;
    struct st_vhttp_http2client_stream_t *stream;
    int ret;

    /* decode */
    if ((ret = vhttp_http2_decode_headers_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if ((frame->stream_id & 1) == 0) {
        *err_desc = "invalid stream id in HEADERS frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    if (frame->stream_id == payload.priority.dependency) {
        *err_desc = "stream cannot depend on itself";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    if ((stream = get_stream(conn, frame->stream_id)) == NULL) {
        if (frame->stream_id > conn->max_open_stream_id) {
            *err_desc = "invalid stream id in HEADERS frame";
            return vhttp_HTTP2_ERROR_PROTOCOL;
        }
    }

    int is_end_stream = (frame->flags & vhttp_HTTP2_FRAME_FLAG_END_STREAM) != 0;

    if (stream != NULL) {
        vhttp_timer_unlink(&stream->super._timeout);

        if (stream->state.res == STREAM_STATE_BODY && !is_end_stream) {
            *err_desc = "trailing HEADERS frame MUST have END_STREAM flag set";
            return vhttp_HTTP2_ERROR_PROTOCOL;
        }
    }

    if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_END_HEADERS) == 0) {
        /* header is not complete, store in buffer */
        conn->input.read_frame = expect_continuation_of_headers;
        vhttp_buffer_init(&conn->input.headers_unparsed, &vhttp_socket_buffer_prototype);
        vhttp_buffer_reserve(&conn->input.headers_unparsed, payload.headers_len);
        memcpy(conn->input.headers_unparsed->bytes, payload.headers, payload.headers_len);
        conn->input.headers_unparsed->size = payload.headers_len;
        return 0;
    }

    /* response header is complete, handle it */
    if (stream != NULL && stream->state.res == STREAM_STATE_BODY) {
        return on_trailers(conn, stream, payload.headers, payload.headers_len, err_desc);
    } else {
        return on_head(conn, stream, payload.headers, payload.headers_len, err_desc, is_end_stream);
    }
}

static int handle_priority_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_priority_t payload;
    int ret;

    if ((ret = vhttp_http2_decode_priority_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (frame->stream_id == payload.dependency) {
        *err_desc = "stream cannot depend on itself";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    /* Ignore PRIORITY frames */
    return 0;
}

static int handle_rst_stream_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_rst_stream_payload_t payload;
    struct st_vhttp_http2client_stream_t *stream;
    int ret;

    if ((ret = vhttp_http2_decode_rst_stream_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (frame->stream_id > conn->max_open_stream_id) {
        *err_desc = "unexpected stream id in RST_STREAM frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    stream = get_stream(conn, frame->stream_id);
    if (stream != NULL) {
        /* reset the stream */
        call_callback_with_error(stream, payload.error_code == -vhttp_HTTP2_ERROR_REFUSED_STREAM ? vhttp_httpclient_error_refused_stream
                                                                                               : vhttp_httpclient_error_io);
        close_stream(stream);
    }

    return 0;
}

static int update_stream_output_window(struct st_vhttp_http2client_stream_t *stream, ssize_t delta)
{
    if (vhttp_http2_window_update(&stream->output.window, delta) != 0)
        return -1;
    ssize_t after = vhttp_http2_window_get_avail(&stream->output.window);
    if (after > 0 && stream->output.buf != NULL && stream->output.buf->size != 0 &&
        !vhttp_linklist_is_linked(&stream->output.sending_link))
        vhttp_linklist_insert(&stream->conn->output.sending_streams, &stream->output.sending_link);
    return 0;
}

static ssize_t conn_get_buffer_window(struct st_vhttp_http2client_conn_t *conn)
{
    ssize_t ret, winsz;
    size_t capacity, cwnd_left;

    capacity = conn->output.buf->capacity;
    if ((cwnd_left = vhttp_socket_prepare_for_latency_optimized_write(conn->super.sock,
                                                                    &conn->super.ctx->http2.latency_optimization)) < capacity) {
        capacity = cwnd_left;
        if (capacity < conn->output.buf->size)
            return 0;
    }

    ret = capacity - conn->output.buf->size;
    if (ret < vhttp_HTTP2_FRAME_HEADER_SIZE)
        return 0;
    ret -= vhttp_HTTP2_FRAME_HEADER_SIZE;
    winsz = vhttp_http2_window_get_avail(&conn->output.window);
    if (winsz < ret)
        ret = winsz;
    return ret;
}

static int handle_settings_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    if (frame->stream_id != 0) {
        *err_desc = "invalid stream id in SETTINGS frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_ACK) != 0) {
        if (frame->length != 0) {
            *err_desc = "invalid SETTINGS frame (+ACK)";
            return vhttp_HTTP2_ERROR_FRAME_SIZE;
        }
    } else {
        uint32_t prev_initial_window_size = conn->peer_settings.initial_window_size;
        int ret = vhttp_http2_update_peer_settings(&conn->peer_settings, frame->payload, frame->length, err_desc);
        if (ret != 0)
            return ret;
        { /* schedule ack */
            vhttp_iovec_t header_buf = vhttp_buffer_reserve(&conn->output.buf, vhttp_HTTP2_FRAME_HEADER_SIZE);
            vhttp_http2_encode_frame_header((void *)header_buf.base, 0, vhttp_HTTP2_FRAME_TYPE_SETTINGS, vhttp_HTTP2_FRAME_FLAG_ACK, 0);
            conn->output.buf->size += vhttp_HTTP2_FRAME_HEADER_SIZE;
            request_write(conn);
        }
        /* apply the change to window size (to all the streams but not the connection, see 6.9.2 of draft-15) */
        if (prev_initial_window_size != conn->peer_settings.initial_window_size) {
            ssize_t delta = conn->peer_settings.initial_window_size - prev_initial_window_size;
            struct st_vhttp_http2client_stream_t *stream;
            kh_foreach_value(conn->streams, stream, { update_stream_output_window((void *)stream, delta); });

            if (conn_get_buffer_window(conn) > 0)
                request_write(conn);
        }
    }

    return 0;
}

static int handle_push_promise_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received PUSH_PROMISE frame";
    return vhttp_HTTP2_ERROR_PROTOCOL;
}

static int handle_ping_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_ping_payload_t payload;
    int ret;

    if ((ret = vhttp_http2_decode_ping_payload(&payload, frame, err_desc)) != 0)
        return ret;

    if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_ACK) == 0) {
        vhttp_http2_encode_ping_frame(&conn->output.buf, 1, payload.data);
        request_write(conn);
    }

    return 0;
}

static int handle_goaway_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_goaway_payload_t payload;
    int ret;

    if ((ret = vhttp_http2_decode_goaway_payload(&payload, frame, err_desc)) != 0)
        return ret;

    struct st_vhttp_http2client_stream_t *stream;
    kh_foreach_value(conn->streams, stream, {
        if (stream->stream_id > payload.last_stream_id) {
            call_callback_with_error(stream, vhttp_httpclient_error_refused_stream);
            close_stream(stream);
        }
    });

    /* stop opening new streams */
    if (vhttp_linklist_is_linked(&conn->super.link))
        vhttp_linklist_unlink(&conn->super.link);

    return 0;
}

static int handle_window_update_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_window_update_payload_t payload;
    int ret, err_is_stream_level;

    if ((ret = vhttp_http2_decode_window_update_payload(&payload, frame, err_desc, &err_is_stream_level)) != 0) {
        if (err_is_stream_level) {
            stream_send_error(conn, frame->stream_id, ret);
            struct st_vhttp_http2client_stream_t *stream = get_stream(conn, frame->stream_id);
            if (stream != NULL) {
                call_callback_with_error(stream, vhttp_httpclient_error_protocol_violation);
                close_stream(stream);
            }
            return 0;
        } else {
            return ret;
        }
    }

    if (frame->stream_id == 0) {
        if (vhttp_http2_window_update(&conn->output.window, payload.window_size_increment) != 0) {
            *err_desc = "flow control window overflow";
            return vhttp_HTTP2_ERROR_FLOW_CONTROL;
        }
    } else if (frame->stream_id <= conn->max_open_stream_id) {
        struct st_vhttp_http2client_stream_t *stream = get_stream(conn, frame->stream_id);
        if (stream != NULL) {
            if (update_stream_output_window(stream, payload.window_size_increment) != 0) {
                stream_send_error(conn, frame->stream_id, vhttp_HTTP2_ERROR_FLOW_CONTROL);
                call_callback_with_error(stream, vhttp_httpclient_error_flow_control);
                close_stream(stream);
                return 0;
            }
        }
    } else {
        *err_desc = "invalid stream id in WINDOW_UPDATE frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    if (conn_get_buffer_window(conn) > 0)
        request_write(conn);

    return 0;
}

static int handle_invalid_continuation_frame(struct st_vhttp_http2client_conn_t *conn, vhttp_http2_frame_t *frame,
                                             const char **err_desc)
{
    *err_desc = "received invalid CONTINUATION frame";
    return vhttp_HTTP2_ERROR_PROTOCOL;
}

ssize_t expect_default(struct st_vhttp_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    assert(conn->state != vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING);

    vhttp_http2_frame_t frame;
    ssize_t ret;
    static int (*FRAME_HANDLERS[])(struct st_vhttp_http2client_conn_t * conn, vhttp_http2_frame_t * frame, const char **err_desc) = {
        handle_data_frame,                /* DATA */
        handle_headers_frame,             /* HEADERS */
        handle_priority_frame,            /* PRIORITY */
        handle_rst_stream_frame,          /* RST_STREAM */
        handle_settings_frame,            /* SETTINGS */
        handle_push_promise_frame,        /* PUSH_PROMISE */
        handle_ping_frame,                /* PING */
        handle_goaway_frame,              /* GOAWAY */
        handle_window_update_frame,       /* WINDOW_UPDATE */
        handle_invalid_continuation_frame /* CONTINUATION */
    };

    if ((ret = vhttp_http2_decode_frame(&frame, src, len, vhttp_HTTP2_SETTINGS_CLIENT_MAX_FRAME_SIZE, err_desc)) < 0)
        return ret;

    if (frame.type < sizeof(FRAME_HANDLERS) / sizeof(FRAME_HANDLERS[0])) {
        int hret = FRAME_HANDLERS[frame.type](conn, &frame, err_desc);
        if (hret != 0)
            ret = hret;
    } else {
        vhttp_error_printf("skipping frame (type:%d)\n", frame.type);
    }

    return ret;
}

static ssize_t expect_settings(struct st_vhttp_http2client_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    assert(conn->state != vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING);

    vhttp_http2_frame_t frame;
    ssize_t ret;

    if ((ret = vhttp_http2_decode_frame(&frame, src, len, vhttp_HTTP2_SETTINGS_CLIENT_MAX_FRAME_SIZE, err_desc)) < 0)
        return ret;

    if (frame.type != vhttp_HTTP2_FRAME_TYPE_SETTINGS)
        return vhttp_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY;

    int hret = handle_settings_frame(conn, &frame, err_desc);
    if (hret != 0)
        return hret;

    conn->input.read_frame = expect_default;
    return ret;
}

static void close_connection_now(struct st_vhttp_http2client_conn_t *conn)
{
    free(conn->super.origin_url.authority.base);
    free(conn->super.origin_url.host.base);
    free(conn->super.origin_url.path.base);

    vhttp_socket_close(conn->super.sock);

    struct st_vhttp_http2client_stream_t *stream;
    kh_foreach_value(conn->streams, stream, { close_stream(stream); });
    kh_destroy(stream, conn->streams);

    if (vhttp_linklist_is_linked(&conn->super.link))
        vhttp_linklist_unlink(&conn->super.link);

    if (vhttp_timer_is_linked(&conn->io_timeout))
        vhttp_timer_unlink(&conn->io_timeout);
    if (vhttp_timer_is_linked(&conn->keepalive_timeout))
        vhttp_timer_unlink(&conn->keepalive_timeout);

    /* output */
    vhttp_hpack_dispose_header_table(&conn->output.header_table);
    vhttp_buffer_dispose(&conn->output.buf);
    if (conn->output.buf_in_flight != NULL)
        vhttp_buffer_dispose(&conn->output.buf_in_flight);
    if (vhttp_timer_is_linked(&conn->output.defer_timeout))
        vhttp_timer_unlink(&conn->output.defer_timeout);
    assert(vhttp_linklist_is_empty(&conn->output.sending_streams));
    assert(vhttp_linklist_is_empty(&conn->output.sent_streams));

    /* input */
    vhttp_hpack_dispose_header_table(&conn->input.header_table);
    if (conn->input.headers_unparsed != NULL)
        vhttp_buffer_dispose(&conn->input.headers_unparsed);

    vhttp_mem_clear_pool(&conn->rst_streams_pool);
    free(conn);
}

static int close_connection_if_necessary(struct st_vhttp_http2client_conn_t *conn)
{
    if (conn->state == vhttp_HTTP2CLIENT_CONN_STATE_HALF_CLOSED && conn->super.num_streams == 0)
        conn->state = vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING;
    if (conn->state == vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING) {
        close_connection_now(conn);
        return 1;
    }
    return 0;
}

static int close_connection(struct st_vhttp_http2client_conn_t *conn)
{
    conn->state = vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING;
    vhttp_socket_read_stop(conn->super.sock);

    if (conn->output.buf_in_flight != NULL || vhttp_timer_is_linked(&conn->output.defer_timeout)) {
        /* there is a pending write, let close_connection_if_necessary actually close the connection */
    } else {
        close_connection_now(conn);
        return -1;
    }
    return 0;
}

static void enqueue_goaway(struct st_vhttp_http2client_conn_t *conn, int errnum, vhttp_iovec_t additional_data)
{
    if (conn->state == vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING)
        return;

    vhttp_http2_encode_goaway_frame(&conn->output.buf, 0, errnum, additional_data);
    request_write(conn);
    conn->state = vhttp_HTTP2CLIENT_CONN_STATE_HALF_CLOSED;

    /* stop opening new streams */
    if (vhttp_linklist_is_linked(&conn->super.link))
        vhttp_linklist_unlink(&conn->super.link);
}

static void on_connect_error(struct st_vhttp_http2client_stream_t *stream, const char *errstr)
{
    assert(errstr != NULL);
    stream->super._cb.on_connect(&stream->super, errstr, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL);
    close_stream(stream);
}

static void do_stream_timeout(struct st_vhttp_http2client_stream_t *stream)
{
    if (stream->conn == NULL) {
        on_connect_error(stream, vhttp_httpclient_error_connect_timeout);
        return;
    }
    const char *errstr =
        stream->state.res == STREAM_STATE_HEAD ? vhttp_httpclient_error_first_byte_timeout : vhttp_httpclient_error_io_timeout;
    call_callback_with_error(stream, errstr);
    close_stream(stream);
}

static void on_stream_timeout(vhttp_timer_t *entry)
{
    struct st_vhttp_http2client_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http2client_stream_t, super._timeout, entry);
    do_stream_timeout(stream);
}

static void on_io_timeout(vhttp_timer_t *entry)
{
    struct st_vhttp_http2client_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http2client_conn_t, io_timeout, entry);
    struct st_vhttp_http2client_stream_t *stream;
    kh_foreach_value(conn->streams, stream, { do_stream_timeout(stream); });
    close_connection_now(conn);
}

static void on_keepalive_timeout(vhttp_timer_t *entry)
{
    struct st_vhttp_http2client_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http2client_conn_t, keepalive_timeout, entry);
    enqueue_goaway(conn, vhttp_HTTP2_ERROR_NONE, vhttp_iovec_init(NULL, 0));
    request_write(conn);
    close_connection(conn);
}

static int parse_input(struct st_vhttp_http2client_conn_t *conn)
{
    /* handle the input */
    while (conn->state != vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING && conn->super.sock->input->size != 0) {
        /* process a frame */
        const char *err_desc = NULL;
        ssize_t ret =
            conn->input.read_frame(conn, (uint8_t *)conn->super.sock->input->bytes, conn->super.sock->input->size, &err_desc);
        if (ret == vhttp_HTTP2_ERROR_INCOMPLETE) {
            break;
        } else if (ret < 0) {
            if (ret != vhttp_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY) {
                enqueue_goaway(conn, (int)ret,
                               err_desc != NULL ? (vhttp_iovec_t){(char *)err_desc, strlen(err_desc)} : (vhttp_iovec_t){NULL});
            }
            call_stream_callbacks_with_error(conn, vhttp_httpclient_error_protocol_violation);
            return close_connection(conn);
        }
        /* advance to the next frame */
        vhttp_buffer_consume(&conn->super.sock->input, ret);
    }
    return 0;
}

static void on_read(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http2client_conn_t *conn = sock->data;

    vhttp_timer_unlink(&conn->io_timeout);

    if (err != NULL) {
        call_stream_callbacks_with_error(conn, vhttp_httpclient_error_io);
        close_connection(conn);
        return;
    }

    if (parse_input(conn) != 0)
        return;

    /* write immediately, if pending write exists */
    if (vhttp_timer_is_linked(&conn->output.defer_timeout)) {
        vhttp_timer_unlink(&conn->output.defer_timeout);
        do_emit_writereq(conn);
    }

    if (!vhttp_timer_is_linked(&conn->io_timeout))
        vhttp_timer_link(conn->super.ctx->loop, conn->super.ctx->io_timeout, &conn->io_timeout);
}

static void on_connection_ready(struct st_vhttp_http2client_stream_t *stream, struct st_vhttp_http2client_conn_t *conn)
{
    vhttp_iovec_t method;
    vhttp_url_t url;
    vhttp_header_t *headers;
    size_t num_headers;
    vhttp_iovec_t body;
    vhttp_httpclient_properties_t props = (vhttp_httpclient_properties_t){NULL};

    register_stream(stream, conn);

    stream->super._cb.on_head =
        stream->super._cb.on_connect(&stream->super, NULL, &method, &url, (const vhttp_header_t **)&headers, &num_headers, &body,
                                     &stream->output.proceed_req, &props, &conn->super.origin_url);
    if (stream->super._cb.on_head == NULL) {
        close_stream(stream);
        return;
    }

    vhttp_http2_window_init(&stream->output.window, conn->peer_settings.initial_window_size);

    /* forward request state */
    if (stream->output.proceed_req != NULL) {
        stream->state.req = STREAM_STATE_BODY;
    } else if (body.base != NULL) {
        stream->state.req = STREAM_STATE_BODY;
    } else {
        stream->state.req = STREAM_STATE_CLOSED;
    }

    if (vhttp_memis(method.base, method.len, vhttp_STRLIT("HEAD"))) {
        stream->input.message_body_forbidden = 1;
    }

    /* send headers */
    vhttp_hpack_flatten_request(&conn->output.buf, &conn->output.header_table, conn->peer_settings.header_table_size,
                              stream->stream_id, conn->peer_settings.max_frame_size, method, &url,
                              stream->super.upgrade_to != NULL && stream->super.upgrade_to != vhttp_httpclient_upgrade_to_connect
                                  ? vhttp_iovec_init(stream->super.upgrade_to, strlen(stream->super.upgrade_to))
                                  : vhttp_iovec_init(NULL, 0),
                              headers, num_headers, stream->state.req == STREAM_STATE_CLOSED);

    if (stream->state.req == STREAM_STATE_BODY) {
        vhttp_buffer_init(&stream->output.buf, &vhttp_socket_buffer_prototype);
        vhttp_buffer_append(&stream->output.buf, body.base, body.len);
    }
    vhttp_linklist_insert(&conn->output.sending_streams, &stream->output.sending_link);
    request_write(conn);
}

static void on_notify_write(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http2client_conn_t *conn = sock->data;

    if (err != NULL) {
        call_stream_callbacks_with_error(conn, vhttp_httpclient_error_io);
        close_connection_now(conn);
        return;
    }
    do_emit_writereq(conn);
    close_connection_if_necessary(conn);
}

static void on_write_complete(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http2client_conn_t *conn = sock->data;

    assert(conn->output.buf_in_flight != NULL);

    vhttp_timer_unlink(&conn->io_timeout);

    /* close by error if necessary */
    if (err != NULL) {
        if (conn->state != vhttp_HTTP2CLIENT_CONN_STATE_IS_CLOSING)
            call_stream_callbacks_with_error(conn, vhttp_httpclient_error_io);
        close_connection_now(conn);
        return;
    }

    if (close_connection_if_necessary(conn))
        return;

    /* unlink timeouts of streams that has finished sending requests */
    while (!vhttp_linklist_is_empty(&conn->output.sent_streams)) {
        vhttp_linklist_t *link = conn->output.sent_streams.next;
        struct st_vhttp_http2client_stream_t *stream =
            vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http2client_stream_t, output.sending_link, link);
        vhttp_linklist_unlink(link);

        /* request the app to send more, unless the stream is already closed (note: invocation of `proceed_req` might invoke
         * `do_write_req` synchronously) */
        int stream_destroyed = 0;
        if (stream->output.proceed_req != NULL) {
            stream->notify_destroyed = &stream_destroyed;
            stream->output.proceed_req(&stream->super, NULL);
            if (stream_destroyed)
                continue;
            stream->notify_destroyed = NULL;
        }

        if (stream->output.proceed_req == NULL && !vhttp_linklist_is_linked(&stream->output.sending_link)) {
            stream->state.req = STREAM_STATE_CLOSED;
            vhttp_timer_link(stream->super.ctx->loop, stream->super.ctx->first_byte_timeout, &stream->super._timeout);
        }
    }

    /* reset the other buffer */
    vhttp_buffer_dispose(&conn->output.buf_in_flight);

    /* bail out if nothing can be written */
    if (conn->output.buf->size == 0 && vhttp_linklist_is_empty(&conn->output.sending_streams)) {
        assert(!vhttp_timer_is_linked(&conn->output.defer_timeout));
        close_connection_if_necessary(conn);
        return;
    }

    /* run next write now instead of relying on the deferred timeout */
    if (vhttp_timer_is_linked(&conn->output.defer_timeout))
        vhttp_timer_unlink(&conn->output.defer_timeout);
#if !vhttp_USE_LIBUV
    if (conn->state == vhttp_HTTP2CLIENT_CONN_STATE_OPEN) {
        vhttp_socket_notify_write(sock, on_notify_write);
        return;
    }
#endif
    do_emit_writereq(conn);
    close_connection_if_necessary(conn);
}

static size_t sz_min(size_t x, size_t y)
{
    return x < y ? x : y;
}

static size_t calc_max_payload_size(struct st_vhttp_http2client_stream_t *stream)
{
    ssize_t conn_max, stream_max;

    if ((conn_max = conn_get_buffer_window(stream->conn)) <= 0)
        return 0;
    if ((stream_max = vhttp_http2_window_get_avail(&stream->output.window)) <= 0)
        return 0;
    return sz_min(sz_min(conn_max, stream_max), stream->conn->peer_settings.max_frame_size);
}

static void stream_emit_pending_data(struct st_vhttp_http2client_stream_t *stream)
{
    size_t max_payload_size = calc_max_payload_size(stream);
    size_t payload_size = sz_min(max_payload_size, stream->output.buf->size);
    int end_stream = stream->output.proceed_req == NULL && payload_size == stream->output.buf->size;
    if (payload_size == 0 && !end_stream)
        return;
    char *dst = vhttp_buffer_reserve(&stream->conn->output.buf, vhttp_HTTP2_FRAME_HEADER_SIZE + payload_size).base;
    vhttp_http2_encode_frame_header((void *)dst, payload_size, vhttp_HTTP2_FRAME_TYPE_DATA,
                                  end_stream ? vhttp_HTTP2_FRAME_FLAG_END_STREAM : 0, stream->stream_id);
    vhttp_memcpy(dst + vhttp_HTTP2_FRAME_HEADER_SIZE, stream->output.buf->bytes, payload_size);
    stream->conn->output.buf->size += vhttp_HTTP2_FRAME_HEADER_SIZE + payload_size;
    vhttp_buffer_consume(&stream->output.buf, payload_size);

    vhttp_http2_window_consume_window(&stream->conn->output.window, payload_size);
    vhttp_http2_window_consume_window(&stream->output.window, payload_size);
}

static void do_emit_writereq(struct st_vhttp_http2client_conn_t *conn)
{
    assert(conn->output.buf_in_flight == NULL);

    /* send DATA frames */
    vhttp_linklist_t pending;
    vhttp_linklist_init_anchor(&pending);
    vhttp_linklist_insert_list(&pending, &conn->output.sending_streams);
    while (!vhttp_linklist_is_empty(&pending)) {
        struct st_vhttp_http2client_stream_t *stream =
            vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http2client_stream_t, output.sending_link, pending.next);
        vhttp_linklist_unlink(&stream->output.sending_link);

        if (stream->output.buf != NULL)
            stream_emit_pending_data(stream);

        if (stream->output.buf == NULL || stream->output.buf->size == 0) {
            vhttp_linklist_insert(&conn->output.sent_streams, &stream->output.sending_link);
        } else if (vhttp_http2_window_get_avail(&stream->output.window) > 0) {
            /* re-insert to tail so that streams would be sent round-robin */
            vhttp_linklist_insert(&conn->output.sending_streams, &stream->output.sending_link);
        } else {
            /* stream is flow-control-blocked; is not linked until WINDOW_UPDATE frame is received */
        }
    }

    if (conn->output.buf->size != 0) {
        /* write and wait for completion */
        vhttp_iovec_t buf = {conn->output.buf->bytes, conn->output.buf->size};
        vhttp_socket_write(conn->super.sock, &buf, 1, on_write_complete);
        conn->output.buf_in_flight = conn->output.buf;
        vhttp_buffer_init(&conn->output.buf, &vhttp_http2_wbuf_buffer_prototype);
        if (!vhttp_timer_is_linked(&conn->io_timeout))
            vhttp_timer_link(conn->super.ctx->loop, conn->super.ctx->io_timeout, &conn->io_timeout);
    }
}

static void emit_writereq(vhttp_timer_t *entry)
{
    struct st_vhttp_http2client_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http2client_conn_t, output.defer_timeout, entry);
    do_emit_writereq(conn);
}

static struct st_vhttp_http2client_conn_t *create_connection(vhttp_httpclient_ctx_t *ctx, vhttp_socket_t *sock, vhttp_url_t *origin_url,
                                                           vhttp_httpclient_connection_pool_t *connpool)
{
    struct st_vhttp_http2client_conn_t *conn = vhttp_mem_alloc(sizeof(*conn));

    memset(conn, 0, offsetof(struct st_vhttp_http2client_conn_t, rst_streams_pool));
    vhttp_mem_init_pool(&conn->rst_streams_pool);

    conn->super.ctx = ctx;
    conn->super.sock = sock;
    conn->state = vhttp_HTTP2CLIENT_CONN_STATE_OPEN;
    conn->peer_settings = vhttp_HTTP2_SETTINGS_DEFAULT;
    conn->streams = kh_init(stream);
    vhttp_url_copy(NULL, &conn->super.origin_url, origin_url);
    if (connpool != NULL)
        vhttp_linklist_insert(&connpool->http2.conns, &conn->super.link);
    conn->io_timeout.cb = on_io_timeout;
    conn->keepalive_timeout.cb = on_keepalive_timeout;

    /* output */
    conn->output.header_table.hpack_capacity = vhttp_HTTP2_SETTINGS_CLIENT_HEADER_TABLE_SIZE;
    vhttp_http2_window_init(&conn->output.window, conn->peer_settings.initial_window_size);
    vhttp_buffer_init(&conn->output.buf, &vhttp_http2_wbuf_buffer_prototype);
    conn->output.defer_timeout.cb = emit_writereq;
    vhttp_linklist_init_anchor(&conn->output.sending_streams);
    vhttp_linklist_init_anchor(&conn->output.sent_streams);

    /* input */
    conn->input.header_table.hpack_capacity = conn->input.header_table.hpack_max_capacity =
        vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size;
    vhttp_http2_window_init(&conn->input.window, vhttp_HTTP2_SETTINGS_DEFAULT.initial_window_size);
    conn->input.read_frame = expect_settings;

    return conn;
}

static void send_client_preface(struct st_vhttp_http2client_conn_t *conn, vhttp_httpclient_ctx_t *ctx)
{
#define PREFIX                                                                                                                     \
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"                                                                                             \
    "\x00\x00\x12"     /* frame size */                                                                                            \
    "\x04"             /* settings frame */                                                                                        \
    "\x00"             /* no flags */                                                                                              \
    "\x00\x00\x00\x00" /* stream id */                                                                                             \
    "\x00\x02"         /* enable_push */                                                                                           \
    "\x00\x00\x00\x00" /* 0 */                                                                                                     \
    "\x00\x03"         /* max_concurrent_streams */                                                                                \
    "\x00\x00\x00\x64" /* 100 */                                                                                                   \
    "\x00\x04"         /* initial_window_size */
    static const size_t len = sizeof(PREFIX) - 1 + 4;

    uint32_t initial_window_size = get_max_buffer_size(ctx);

    vhttp_iovec_t vec = vhttp_buffer_reserve(&conn->output.buf, len);
    memcpy(vec.base, PREFIX, sizeof(PREFIX) - 1);

    /* encode max_buffer_size */
    vec.base[len - 4] = (char)((initial_window_size >> 24) & 0xff);
    vec.base[len - 3] = (char)((initial_window_size >> 16) & 0xff);
    vec.base[len - 2] = (char)((initial_window_size >> 8) & 0xff);
    vec.base[len - 1] = (char)(initial_window_size & 0xff);

    conn->output.buf->size += len;
    request_write(conn);
#undef PREFIX
}

static void do_cancel(vhttp_httpclient_t *_client)
{
    struct st_vhttp_http2client_stream_t *stream = (void *)_client;
    stream_send_error(stream->conn, stream->stream_id, vhttp_HTTP2_ERROR_CANCEL);
    close_stream(stream);
}

static void do_get_conn_properties(vhttp_httpclient_t *_client, vhttp_httpclient_conn_properties_t *properties)
{
    struct st_vhttp_http2client_stream_t *stream = (void *)_client;
    vhttp_httpclient_set_conn_properties_of_socket(stream->conn->super.sock, properties);
}

static void do_update_window(vhttp_httpclient_t *_client)
{
    struct st_vhttp_http2client_stream_t *stream = (void *)_client;
    size_t max = get_max_buffer_size(stream->super.ctx);
    size_t bufsize = stream->input.body->size;
    assert(bufsize <= max);
    enqueue_window_update(stream->conn, stream->stream_id, &stream->input.window, max - bufsize);
}

static int do_write_req(vhttp_httpclient_t *_client, vhttp_iovec_t chunk, int is_end_stream)
{
    struct st_vhttp_http2client_stream_t *stream = (void *)_client;
    assert(stream->output.proceed_req != NULL);
    assert(!vhttp_linklist_is_linked(&stream->output.sending_link));

    if (is_end_stream)
        stream->output.proceed_req = NULL;

    if (stream->output.buf == NULL)
        vhttp_buffer_init(&stream->output.buf, &vhttp_socket_buffer_prototype);

    if (chunk.len != 0)
        vhttp_buffer_append(&stream->output.buf, chunk.base, chunk.len);

    vhttp_linklist_insert(&stream->conn->output.sending_streams, &stream->output.sending_link);
    request_write(stream->conn);

    return 0;
}

static void setup_stream(struct st_vhttp_http2client_stream_t *stream)
{
    memset(&stream->conn, 0, sizeof(*stream) - offsetof(struct st_vhttp_http2client_stream_t, conn));

    stream->super._timeout.cb = on_stream_timeout;
    vhttp_http2_window_init(&stream->input.window, get_max_buffer_size(stream->super.ctx));
    vhttp_buffer_init(&stream->input.body, &vhttp_socket_buffer_prototype);
    stream->input.remaining_content_length = SIZE_MAX;
    stream->input.message_body_forbidden = 0;

    stream->super.buf = &stream->input.body;
    stream->super.cancel = do_cancel;
    stream->super.get_conn_properties = do_get_conn_properties;
    stream->super.update_window = do_update_window;
    stream->super.write_req = do_write_req;
}

void vhttp_httpclient__h2_on_connect(vhttp_httpclient_t *_client, vhttp_socket_t *sock, vhttp_url_t *origin)
{
    struct st_vhttp_http2client_stream_t *stream = (void *)_client;

    assert(!vhttp_timer_is_linked(&stream->super._timeout));

    struct st_vhttp_http2client_conn_t *conn = sock->data;
    if (conn == NULL) {
        conn = create_connection(stream->super.ctx, sock, origin, stream->super.connpool);
        sock->data = conn;
        /* send preface, settings, and connection-level window update */
        send_client_preface(conn, stream->super.ctx);
        vhttp_socket_read_start(conn->super.sock, on_read);
    }

    setup_stream(stream);

    if (!vhttp_timer_is_linked(&conn->io_timeout))
        vhttp_timer_link(conn->super.ctx->loop, conn->super.ctx->io_timeout, &conn->io_timeout);
    on_connection_ready(stream, conn);
}

const size_t vhttp_httpclient__h2_size = sizeof(struct st_vhttp_http2client_stream_t);
