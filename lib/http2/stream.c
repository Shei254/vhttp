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
#include "vhttp.h"
#include "vhttp/http2.h"
#include "vhttp/http2_internal.h"
#include "vhttp/absprio.h"
#include "../probes_.h"

static void finalostream_send(vhttp_ostream_t *self, vhttp_req_t *req, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_send_state_t state);
static void finalostream_send_informational(vhttp_ostream_t *_self, vhttp_req_t *req);

static size_t sz_min(size_t x, size_t y)
{
    return x < y ? x : y;
}

vhttp_http2_stream_t *vhttp_http2_stream_open(vhttp_http2_conn_t *conn, uint32_t stream_id, vhttp_req_t *src_req,
                                          const vhttp_http2_priority_t *received_priority)
{
    vhttp_http2_stream_t *stream = vhttp_mem_alloc(sizeof(*stream));

    /* init properties (other than req) */
    memset(stream, 0, offsetof(vhttp_http2_stream_t, req));
    stream->stream_id = stream_id;
    stream->_ostr_final.do_send = finalostream_send;
    stream->_ostr_final.send_informational =
        conn->super.ctx->globalconf->send_informational_mode == vhttp_SEND_INFORMATIONAL_MODE_NONE ? NULL
                                                                                                 : finalostream_send_informational;
    stream->state = vhttp_HTTP2_STREAM_STATE_IDLE;
    vhttp_http2_window_init(&stream->output_window, conn->peer_settings.initial_window_size);
    vhttp_http2_window_init(&stream->input_window.window, vhttp_HTTP2_SETTINGS_HOST_STREAM_INITIAL_WINDOW_SIZE);
    stream->received_priority = *received_priority;

    /* init request */
    vhttp_init_request(&stream->req, &conn->super, src_req);
    stream->req.version = 0x200;
    if (src_req != NULL)
        memset(&stream->req.upgrade, 0, sizeof(stream->req.upgrade));
    stream->req._ostr_top = &stream->_ostr_final;

    vhttp_http2_conn_register_stream(conn, stream);

    ++conn->num_streams.priority.open;
    stream->_num_streams_slot = &conn->num_streams.priority;

    return stream;
}

void vhttp_http2_stream_close(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    vhttp_http2_conn_unregister_stream(conn, stream);
    if (stream->cache_digests != NULL)
        vhttp_cache_digests_destroy(stream->cache_digests);
    if (stream->req_body.buf != NULL)
        vhttp_buffer_dispose(&stream->req_body.buf);
    vhttp_dispose_request(&stream->req);
    if (stream->stream_id == 1 && conn->_http1_req_input != NULL)
        vhttp_buffer_dispose(&conn->_http1_req_input);
    free(stream);
}

void vhttp_http2_stream_reset(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    switch (stream->state) {
    case vhttp_HTTP2_STREAM_STATE_IDLE:
    case vhttp_HTTP2_STREAM_STATE_RECV_HEADERS:
    case vhttp_HTTP2_STREAM_STATE_RECV_BODY:
    case vhttp_HTTP2_STREAM_STATE_REQ_PENDING:
        vhttp_http2_stream_close(conn, stream);
        break;
    case vhttp_HTTP2_STREAM_STATE_SEND_HEADERS:
    case vhttp_HTTP2_STREAM_STATE_SEND_BODY:
    case vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
        vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_END_STREAM);
    /* continues */
    case vhttp_HTTP2_STREAM_STATE_END_STREAM:
        /* clear all the queued bufs, and close the connection in the callback */
        stream->_data.size = 0;
        if (vhttp_linklist_is_linked(&stream->_link)) {
            /* will be closed in the callback */
        } else {
            vhttp_http2_stream_close(conn, stream);
        }
        break;
    }
}

static size_t calc_max_payload_size(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    ssize_t conn_max, stream_max;

    if ((conn_max = vhttp_http2_conn_get_buffer_window(conn)) <= 0)
        return 0;
    if ((stream_max = vhttp_http2_window_get_avail(&stream->output_window)) <= 0)
        return 0;
    return sz_min(sz_min(conn_max, stream_max), conn->peer_settings.max_frame_size);
}

static void commit_data_header(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, vhttp_buffer_t **outbuf, size_t length,
                               vhttp_send_state_t send_state)
{
    assert(outbuf != NULL);
    /* send a DATA frame if there's data or the END_STREAM flag to send */
    int is_end_stream = send_state == vhttp_SEND_STATE_FINAL && !stream->req.send_server_timing && stream->req.res.trailers.size == 0;
    if (length != 0 || is_end_stream) {
        vhttp_http2_encode_frame_header((void *)((*outbuf)->bytes + (*outbuf)->size), length, vhttp_HTTP2_FRAME_TYPE_DATA,
                                      is_end_stream ? vhttp_HTTP2_FRAME_FLAG_END_STREAM : 0, stream->stream_id);
        vhttp_http2_window_consume_window(&conn->_write.window, length);
        vhttp_http2_window_consume_window(&stream->output_window, length);
        (*outbuf)->size += length + vhttp_HTTP2_FRAME_HEADER_SIZE;
        stream->req.bytes_sent += length;
    }
    /* send a RST_STREAM if there's an error */
    if (send_state == vhttp_SEND_STATE_ERROR) {
        vhttp_http2_encode_rst_stream_frame(
            outbuf, stream->stream_id, -(stream->req.upstream_refused ? vhttp_HTTP2_ERROR_REFUSED_STREAM : vhttp_HTTP2_ERROR_PROTOCOL));
    }
}

static vhttp_sendvec_t *send_data(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, vhttp_sendvec_t *bufs, size_t bufcnt,
                                vhttp_send_state_t send_state)
{
    vhttp_iovec_t dst;
    size_t max_payload_size;

    if ((max_payload_size = calc_max_payload_size(conn, stream)) == 0)
        goto Exit;

    /* reserve buffer and point dst to the payload */
    dst.base =
        vhttp_buffer_reserve(&conn->_write.buf, vhttp_HTTP2_FRAME_HEADER_SIZE + max_payload_size).base + vhttp_HTTP2_FRAME_HEADER_SIZE;
    dst.len = max_payload_size;

    /* emit data */
    while (bufcnt != 0) {
        size_t fill_size = sz_min(dst.len, bufs->len);
        if (!(*bufs->callbacks->read_)(bufs, dst.base, fill_size)) {
            vhttp_http2_encode_rst_stream_frame(&conn->_write.buf, stream->stream_id, -vhttp_HTTP2_ERROR_INTERNAL);
            return NULL;
        }
        dst.base += fill_size;
        dst.len -= fill_size;
        if (bufs->len == 0) {
            ++bufs;
            --bufcnt;
            if (bufcnt == 0)
                break;
        }
        if (dst.len == 0)
            break;
    }

    /* commit the DATA frame if we have actually emitted payload */
    if (dst.len != max_payload_size || !vhttp_send_state_is_in_progress(send_state)) {
        size_t payload_len = max_payload_size - dst.len;
        if (bufcnt != 0) {
            send_state = vhttp_SEND_STATE_IN_PROGRESS;
        }
        commit_data_header(conn, stream, &conn->_write.buf, payload_len, send_state);
    }

Exit:
    return bufs;
}

static int is_blocking_asset(vhttp_req_t *req)
{
    if (req->res.mime_attr == NULL)
        vhttp_req_fill_mime_attributes(req);
    return req->res.mime_attr->priority == vhttp_MIME_ATTRIBUTE_PRIORITY_HIGHEST;
}

static void request_write_and_close(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_END_STREAM);
    vhttp_http2_scheduler_deactivate(&stream->_scheduler);
    if (!vhttp_linklist_is_linked(&stream->_link))
        vhttp_linklist_insert(&conn->_write.streams_to_proceed, &stream->_link);
    vhttp_http2_conn_request_write(conn);
}

static void send_refused_stream(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    vhttp_http2_encode_rst_stream_frame(&conn->_write.buf, stream->stream_id, -vhttp_HTTP2_ERROR_REFUSED_STREAM);
    request_write_and_close(conn, stream);
}

static int send_headers(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, int is_end_stream)
{
    stream->req.timestamps.response_start_at = vhttp_gettimeofday(conn->super.ctx->loop);

    /* cancel push with an error response */
    if (vhttp_http2_stream_is_push(stream->stream_id)) {
        if (400 <= stream->req.res.status)
            goto CancelPush;
        if (stream->cache_digests != NULL) {
            ssize_t etag_index = vhttp_find_header(&stream->req.headers, vhttp_TOKEN_ETAG, -1);
            if (etag_index != -1) {
                vhttp_iovec_t url = vhttp_concat(&stream->req.pool, stream->req.input.scheme->name, vhttp_iovec_init(vhttp_STRLIT("://")),
                                             stream->req.input.authority, stream->req.input.path);
                vhttp_iovec_t *etag = &stream->req.headers.entries[etag_index].value;
                if (vhttp_cache_digests_lookup_by_url_and_etag(stream->cache_digests, url.base, url.len, etag->base, etag->len) ==
                    vhttp_CACHE_DIGESTS_STATE_FRESH)
                    goto CancelPush;
            }
        }
    }

    /* reset casper cookie in case cache-digests exist */
    if (stream->cache_digests != NULL && stream->req.hostconf->http2.casper.capacity_bits != 0) {
        vhttp_add_header(&stream->req.pool, &stream->req.res.headers, vhttp_TOKEN_SET_COOKIE, NULL,
                       vhttp_STRLIT("vhttp_casper=; Path=/; Expires=Sat, 01 Jan 2000 00:00:00 GMT"));
    }

    /* CASPER */
    if (conn->casper != NULL) {
        /* update casper if necessary */
        if (stream->req.hostconf->http2.casper.track_all_types || is_blocking_asset(&stream->req)) {
            if (vhttp_http2_casper_lookup(conn->casper, stream->req.path.base, stream->req.path.len, 1)) {
                /* cancel if the pushed resource is already marked as cached */
                if (vhttp_http2_stream_is_push(stream->stream_id))
                    goto CancelPush;
            }
        }
        if (stream->cache_digests != NULL)
            goto SkipCookie;
        /* browsers might ignore push responses, or they may process the responses in a different order than they were pushed.
         * Therefore vhttp tries to include casper cookie only in the last stream that may be received by the client, or when the
         * value become stable; see also: https://github.com/vhttp/vhttp/issues/421
         */
        if (vhttp_http2_stream_is_push(stream->stream_id)) {
            if (!(conn->num_streams.pull.open == 0 && (conn->num_streams.push.half_closed - conn->num_streams.push.send_body) == 1))
                goto SkipCookie;
        } else {
            if (conn->num_streams.push.half_closed - conn->num_streams.push.send_body != 0)
                goto SkipCookie;
        }
        vhttp_iovec_t cookie = vhttp_http2_casper_get_cookie(conn->casper);
        vhttp_add_header(&stream->req.pool, &stream->req.res.headers, vhttp_TOKEN_SET_COOKIE, NULL, cookie.base, cookie.len);
    SkipCookie:;
    }

    if (vhttp_http2_stream_is_push(stream->stream_id)) {
        /* for push, send the push promise */
        if (!stream->push.promise_sent)
            vhttp_http2_stream_send_push_promise(conn, stream);
        /* send ASAP if it is a blocking asset (even in case of Firefox we can't wait 1RTT for it to reprioritize the asset) */
        if (is_blocking_asset(&stream->req))
            vhttp_http2_scheduler_rebind(&stream->_scheduler, &conn->scheduler, 257, 0);
    } else {
        /* Handle absolute priority header */
        ssize_t absprio_cursor = vhttp_find_header(&stream->req.res.headers, vhttp_TOKEN_PRIORITY, -1);
        if (absprio_cursor != -1 && conn->is_chromium_dependency_tree) {
            /* Found absolute priority header in the response header */
            vhttp_absprio_t prio = vhttp_absprio_default;
            vhttp_iovec_t *header_value = &stream->req.res.headers.entries[absprio_cursor].value;
            vhttp_absprio_parse_priority(header_value->base, header_value->len, &prio);
            uint16_t new_weight = vhttp_absprio_urgency_to_chromium_weight(prio.urgency);
            vhttp_http2_scheduler_node_t *new_parent = vhttp_http2_scheduler_find_parent_by_weight(&conn->scheduler, new_weight);
            if (new_parent == &stream->_scheduler.node) {
                /* find_new_parent might return `stream` itself. In this case re-specify the current
                 * parent as a new parent */
                new_parent = vhttp_http2_scheduler_get_parent(&stream->_scheduler);
            }
            if (new_parent != vhttp_http2_scheduler_get_parent(&stream->_scheduler) ||
                new_weight != vhttp_http2_scheduler_get_weight(&stream->_scheduler)) {
                /* Reprioritize the stream based on priority header information */

                /* First, preserve the current (client-given) priority information so that subsequent
                 * streams from the client can correctly refer to the original priority. */
                vhttp_http2_conn_preserve_stream_scheduler(conn, stream);
                /* Open a new scheduler for the modified priority information for this stream */
                vhttp_http2_scheduler_open(&stream->_scheduler, new_parent, new_weight, 1);
            }
        } else if (conn->num_streams.priority.open == 0 && stream->req.hostconf->http2.reprioritize_blocking_assets &&
                   vhttp_http2_scheduler_get_parent(&stream->_scheduler) == &conn->scheduler && is_blocking_asset(&stream->req)) {
            /* raise the priority of asset files that block rendering to highest if the user-agent is _not_ using dependency-based
             * prioritization (e.g. that of Firefox)
             */
            vhttp_http2_scheduler_rebind(&stream->_scheduler, &conn->scheduler, 257, 0);
        }
    }

    /* send HEADERS, as well as start sending body */
    if (vhttp_http2_stream_is_push(stream->stream_id))
        vhttp_add_header_by_str(&stream->req.pool, &stream->req.res.headers, vhttp_STRLIT("x-http2-push"), 0, NULL,
                              vhttp_STRLIT("pushed"));
    if (stream->req.send_server_timing)
        vhttp_add_server_timing_header(&stream->req, 1);
    stream->req.header_bytes_sent += vhttp_hpack_flatten_response(
        &conn->_write.buf, &conn->_output_header_table, conn->peer_settings.header_table_size, stream->stream_id,
        conn->peer_settings.max_frame_size, stream->req.res.status, stream->req.res.headers.entries, stream->req.res.headers.size,
        &conn->super.ctx->globalconf->server_name, stream->req.res.content_length, is_end_stream);
    vhttp_http2_conn_request_write(conn);
    vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_SEND_BODY);

    return 0;

CancelPush:
    vhttp_add_header_by_str(&stream->req.pool, &stream->req.res.headers, vhttp_STRLIT("x-http2-push"), 0, NULL,
                          vhttp_STRLIT("cancelled"));
    vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_END_STREAM);
    vhttp_linklist_insert(&conn->_write.streams_to_proceed, &stream->_link);
    if (stream->push.promise_sent) {
        vhttp_http2_encode_rst_stream_frame(&conn->_write.buf, stream->stream_id, -vhttp_HTTP2_ERROR_INTERNAL);
        vhttp_http2_conn_request_write(conn);
    }
    return -1;
}

void finalostream_send(vhttp_ostream_t *self, vhttp_req_t *req, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_send_state_t state)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, _ostr_final, self);
    vhttp_http2_conn_t *conn = (vhttp_http2_conn_t *)req->conn;

    assert(vhttp_send_state_is_in_progress(stream->send_state));
    assert(stream->_data.size == 0);

    if (stream->blocked_by_server)
        vhttp_http2_stream_set_blocked_by_server(conn, stream, 0);

    if (stream->req.res.status == 425 && stream->req.reprocess_if_too_early) {
        assert(stream->state <= vhttp_HTTP2_STREAM_STATE_SEND_HEADERS);
        vhttp_http2_conn_register_for_replay(conn, stream);
        return;
    }

    stream->send_state = state;
    int is_end_stream = state == vhttp_SEND_STATE_FINAL && bufcnt == 0;

    /* send headers */
    switch (stream->state) {
    case vhttp_HTTP2_STREAM_STATE_RECV_BODY:
        vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_REQ_PENDING);
    /* fallthru */
    case vhttp_HTTP2_STREAM_STATE_REQ_PENDING:
        vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_SEND_HEADERS);
    /* fallthru */
    case vhttp_HTTP2_STREAM_STATE_SEND_HEADERS:
        if (stream->req.upstream_refused) {
            send_refused_stream(conn, stream);
            return;
        }
        vhttp_probe_log_response(&stream->req, stream->stream_id);
        if (send_headers(conn, stream, is_end_stream) != 0)
            return;
        if (is_end_stream) {
            request_write_and_close(conn, stream);
            return;
        }
    /* fallthru */
    case vhttp_HTTP2_STREAM_STATE_SEND_BODY:
        if (state != vhttp_SEND_STATE_IN_PROGRESS) {
            vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL);
        }
        break;
    case vhttp_HTTP2_STREAM_STATE_END_STREAM:
        /* might get set by vhttp_http2_stream_reset */
        return;
    default:
        assert(!"cannot be in a receiving state");
    }

    /* save the contents in queue */
    if (bufcnt != 0) {
        vhttp_vector_reserve(&req->pool, &stream->_data, bufcnt);
        memcpy(stream->_data.entries, bufs, sizeof(*bufs) * bufcnt);
        stream->_data.size = bufcnt;
    }

    vhttp_http2_conn_register_for_proceed_callback(conn, stream);
}

static void finalostream_send_informational(vhttp_ostream_t *self, vhttp_req_t *req)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, _ostr_final, self);
    vhttp_http2_conn_t *conn = (vhttp_http2_conn_t *)req->conn;

    stream->req.header_bytes_sent += vhttp_hpack_flatten_response(
        &conn->_write.buf, &conn->_output_header_table, conn->peer_settings.header_table_size, stream->stream_id,
        conn->peer_settings.max_frame_size, req->res.status, req->res.headers.entries, req->res.headers.size, NULL, SIZE_MAX, 0);
    vhttp_http2_conn_request_write(conn);
}

void vhttp_http2_stream_send_pending_data(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    if (vhttp_http2_window_get_avail(&stream->output_window) <= 0)
        return;

    vhttp_sendvec_t *nextbuf = send_data(conn, stream, stream->_data.entries, stream->_data.size, stream->send_state);
    if (nextbuf == NULL && stream->_data.entries != NULL) {
        /* error */
        stream->_data.size = 0;
        stream->send_state = vhttp_SEND_STATE_ERROR;
        vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_END_STREAM);
    } else if (nextbuf == stream->_data.entries + stream->_data.size) {
        /* sent all data */
        stream->_data.size = 0;
        if (stream->state == vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL)
            vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_END_STREAM);
    } else if (nextbuf != stream->_data.entries) {
        /* adjust the buffer */
        size_t newsize = stream->_data.size - (nextbuf - stream->_data.entries);
        memmove(stream->_data.entries, nextbuf, sizeof(stream->_data.entries[0]) * newsize);
        stream->_data.size = newsize;
    }

    /* if the stream entered error state, suppress sending trailers */
    if (stream->send_state == vhttp_SEND_STATE_ERROR)
        stream->req.send_server_timing = 0;
}

void vhttp_http2_stream_proceed(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    if (stream->state == vhttp_HTTP2_STREAM_STATE_END_STREAM) {
        switch (stream->req_body.state) {
        case vhttp_HTTP2_REQ_BODY_NONE:
        case vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED:
            vhttp_http2_stream_close(conn, stream);
            break;
        default:
            break; /* the stream will be closed when the read side is done */
        }
    } else {
        if (!stream->blocked_by_server)
            vhttp_http2_stream_set_blocked_by_server(conn, stream, 1);
        vhttp_proceed_response(&stream->req);
    }
}
