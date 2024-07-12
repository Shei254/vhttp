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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "vhttp.h"
#include "vhttp/hpack.h"
#include "vhttp/http1.h"
#include "vhttp/http2.h"
#include "vhttp/http2_internal.h"
#include "vhttp/absprio.h"
#include "../probes_.h"

static const vhttp_iovec_t CONNECTION_PREFACE = {vhttp_STRLIT("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")};

vhttp_buffer_prototype_t vhttp_http2_wbuf_buffer_prototype = {{vhttp_HTTP2_DEFAULT_OUTBUF_SIZE}};

static void update_stream_input_window(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, size_t bytes);
static void proceed_request(vhttp_req_t *req, const char *errstr);
static void initiate_graceful_shutdown(vhttp_conn_t *_conn);
static void close_connection_now(vhttp_http2_conn_t *conn);
static int close_connection(vhttp_http2_conn_t *conn);
static ssize_t expect_default(vhttp_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
static void do_emit_writereq(vhttp_http2_conn_t *conn);
static void on_read(vhttp_socket_t *sock, const char *err);
static void push_path(vhttp_req_t *src_req, const char *abspath, size_t abspath_len, int is_critical);
static int foreach_request(vhttp_conn_t *_conn, int (*cb)(vhttp_req_t *req, void *cbdata), void *cbdata);
static void stream_send_error(vhttp_http2_conn_t *conn, uint32_t stream_id, int errnum);

static int is_idle_stream_id(vhttp_http2_conn_t *conn, uint32_t stream_id)
{
    return (vhttp_http2_stream_is_push(stream_id) ? conn->push_stream_ids.max_open : conn->pull_stream_ids.max_open) < stream_id;
}

static void enqueue_goaway(vhttp_http2_conn_t *conn, int errnum, vhttp_iovec_t additional_data)
{
    if (conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING) {
        /* http2 spec allows sending GOAWAY more than once (for one reason since errors may arise after sending the first one) */
        vhttp_http2_encode_goaway_frame(&conn->_write.buf, conn->pull_stream_ids.max_open, errnum, additional_data);
        vhttp_http2_conn_request_write(conn);
        conn->state = vhttp_HTTP2_CONN_STATE_HALF_CLOSED;
    }
}

static void enqueue_server_preface(vhttp_http2_conn_t *conn)
{
    /* Send settings and initial window update */
    vhttp_http2_settings_kvpair_t settings[] = {
        {vhttp_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, conn->super.ctx->globalconf->http2.max_streams},
        {vhttp_HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1}};
    vhttp_http2_encode_settings_frame(&conn->_write.buf, settings, PTLS_ELEMENTSOF(settings));
    vhttp_http2_encode_window_update_frame(
        &conn->_write.buf, 0, vhttp_HTTP2_SETTINGS_HOST_CONNECTION_WINDOW_SIZE - vhttp_HTTP2_SETTINGS_HOST_STREAM_INITIAL_WINDOW_SIZE);
}

static void graceful_shutdown_close_straggler(vhttp_timer_t *entry)
{
    vhttp_http2_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_conn_t, _graceful_shutdown_timeout, entry);
    /* We've sent two GOAWAY frames, close the remaining connections */
    close_connection(conn);
}

static void graceful_shutdown_resend_goaway(vhttp_timer_t *entry)
{
    vhttp_http2_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_conn_t, _graceful_shutdown_timeout, entry);

    if (conn->state < vhttp_HTTP2_CONN_STATE_HALF_CLOSED) {
        enqueue_goaway(conn, vhttp_HTTP2_ERROR_NONE, (vhttp_iovec_t){NULL});

        /* After waiting a second, we still have an active connection. If configured, wait one
         * final timeout before closing the connection */
        if (conn->super.ctx->globalconf->http2.graceful_shutdown_timeout > 0) {
            conn->_graceful_shutdown_timeout.cb = graceful_shutdown_close_straggler;
            vhttp_timer_link(conn->super.ctx->loop, conn->super.ctx->globalconf->http2.graceful_shutdown_timeout,
                           &conn->_graceful_shutdown_timeout);
        }
    }
}

static void close_idle_connection(vhttp_conn_t *_conn)
{
    initiate_graceful_shutdown(_conn);
}

static void initiate_graceful_shutdown(vhttp_conn_t *_conn)
{
    vhttp_conn_set_state(_conn, vhttp_CONN_STATE_SHUTDOWN);

    /* draft-16 6.8
     * A server that is attempting to gracefully shut down a connection SHOULD send an initial GOAWAY frame with the last stream
     * identifier set to 231-1 and a NO_ERROR code. This signals to the client that a shutdown is imminent and that no further
     * requests can be initiated. After waiting at least one round trip time, the server can send another GOAWAY frame with an
     * updated last stream identifier. This ensures that a connection can be cleanly shut down without losing requests.
     */

    vhttp_http2_conn_t *conn = (void *)_conn;
    assert(conn->_graceful_shutdown_timeout.cb == NULL);
    conn->_graceful_shutdown_timeout.cb = graceful_shutdown_resend_goaway;

    if (conn->state < vhttp_HTTP2_CONN_STATE_HALF_CLOSED) {
        vhttp_http2_encode_goaway_frame(&conn->_write.buf, INT32_MAX, vhttp_HTTP2_ERROR_NONE,
                                      (vhttp_iovec_t){vhttp_STRLIT("graceful shutdown")});
        vhttp_http2_conn_request_write(conn);
    }

    vhttp_timer_link(conn->super.ctx->loop, 1000, &conn->_graceful_shutdown_timeout);
}

static void on_idle_timeout(vhttp_timer_t *entry)
{
    vhttp_http2_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_conn_t, _timeout_entry, entry);
    conn->super.ctx->http2.events.idle_timeouts++;

    if (conn->_write.buf_in_flight != NULL) {
        close_connection_now(conn);
    } else {
        enqueue_goaway(conn, vhttp_HTTP2_ERROR_NONE, vhttp_iovec_init(vhttp_STRLIT("idle timeout")));
        close_connection(conn);
    }
}

static void update_idle_timeout(vhttp_http2_conn_t *conn)
{
    /* do nothing touch anything if write is in progress */
    if (conn->_write.buf_in_flight != NULL) {
        assert(vhttp_timer_is_linked(&conn->_timeout_entry));
        return;
    }

    vhttp_timer_unlink(&conn->_timeout_entry);

    /* always set idle timeout if TLS handshake is in progress */
    if (conn->sock->ssl != NULL && vhttp_socket_ssl_is_early_data(conn->sock))
        goto SetTimeout;

    /* no need to set timeout if pending requests exist */
    if (conn->num_streams.blocked_by_server != 0)
        return;

SetTimeout:
    conn->_timeout_entry.cb = on_idle_timeout;
    vhttp_timer_link(conn->super.ctx->loop, conn->super.ctx->globalconf->http2.idle_timeout, &conn->_timeout_entry);
}

static int can_run_requests(vhttp_http2_conn_t *conn)
{
    return conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed <
           conn->super.ctx->globalconf->http2.max_concurrent_requests_per_connection;
}

static void process_request(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    if (stream->req.proceed_req != NULL) {
        assert(
            !(stream->req_body.state == vhttp_HTTP2_REQ_BODY_NONE || stream->req_body.state == vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED));
        conn->num_streams._req_streaming_in_progress++;
        conn->super.ctx->http2.events.streaming_requests++;
        stream->req_body.streamed = 1;
        if (stream->req.is_tunnel_req)
            conn->num_streams.tunnel++;
        update_stream_input_window(conn, stream,
                                   conn->super.ctx->globalconf->http2.active_stream_window_size -
                                       vhttp_HTTP2_SETTINGS_HOST_STREAM_INITIAL_WINDOW_SIZE);
    } else {
        if (stream->state < vhttp_HTTP2_STREAM_STATE_SEND_HEADERS) {
            vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_REQ_PENDING);
            vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_SEND_HEADERS);
        }
    }

    if (!vhttp_http2_stream_is_push(stream->stream_id) && conn->pull_stream_ids.max_processed < stream->stream_id)
        conn->pull_stream_ids.max_processed = stream->stream_id;

    vhttp_process_request(&stream->req);
}

static void run_pending_requests(vhttp_http2_conn_t *conn)
{
    if (vhttp_timer_is_linked(&conn->dos_mitigation.process_delay))
        return;

    vhttp_linklist_t *link, *lnext;
    int ran_one_request;

    do {
        ran_one_request = 0;

        for (link = conn->_pending_reqs.next; link != &conn->_pending_reqs && can_run_requests(conn); link = lnext) {
            /* fetch and detach a pending stream */
            vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, _link, link);

            lnext = link->next;

            /* handle no more than specified number of streaming requests at a time */
            if (stream->req.proceed_req != NULL &&
                conn->num_streams._req_streaming_in_progress - conn->num_streams.tunnel >=
                    conn->super.ctx->globalconf->http2.max_concurrent_streaming_requests_per_connection)
                continue;

            /* handle it */
            vhttp_linklist_unlink(&stream->_link);
            ran_one_request = 1;
            process_request(conn, stream);
        }

    } while (ran_one_request && !vhttp_linklist_is_empty(&conn->_pending_reqs));
}

static int reset_stream_if_disregarded(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    if (!vhttp_http2_stream_is_push(stream->stream_id) && stream->stream_id > conn->pull_stream_ids.max_open) {
        /* this stream is opened after sending GOAWAY, so ignore it */
        vhttp_http2_stream_reset(conn, stream);
        return 1;
    }
    return 0;
}

static void execute_or_enqueue_request_core(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    /* TODO schedule the pending reqs using the scheduler */
    vhttp_linklist_insert(&conn->_pending_reqs, &stream->_link);

    run_pending_requests(conn);
    update_idle_timeout(conn);
}

static void execute_or_enqueue_request(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    assert(stream->state == vhttp_HTTP2_STREAM_STATE_RECV_HEADERS || stream->state == vhttp_HTTP2_STREAM_STATE_REQ_PENDING);

    if (reset_stream_if_disregarded(conn, stream))
        return;

    vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_REQ_PENDING);
    if (!stream->blocked_by_server)
        vhttp_http2_stream_set_blocked_by_server(conn, stream, 1);
    execute_or_enqueue_request_core(conn, stream);
}

void vhttp_http2_conn_register_stream(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    khiter_t iter;
    int r;

    iter = kh_put(vhttp_http2_stream_t, conn->streams, stream->stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;
}

void vhttp_http2_conn_preserve_stream_scheduler(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *src)
{
    assert(vhttp_http2_scheduler_is_open(&src->_scheduler));

    vhttp_http2_stream_t **dst = conn->_recently_closed_streams.streams + conn->_recently_closed_streams.next_slot;
    if (++conn->_recently_closed_streams.next_slot == HTTP2_CLOSED_STREAM_PRIORITIES)
        conn->_recently_closed_streams.next_slot = 0;

    if (*dst != NULL) {
        assert(vhttp_http2_scheduler_is_open(&(*dst)->_scheduler));
        vhttp_http2_scheduler_close(&(*dst)->_scheduler);
    } else {
        *dst = vhttp_mem_alloc(offsetof(vhttp_http2_stream_t, _scheduler) + sizeof((*dst)->_scheduler));
    }

    (*dst)->stream_id = src->stream_id;
    vhttp_http2_scheduler_relocate(&(*dst)->_scheduler, &src->_scheduler);
    vhttp_http2_scheduler_deactivate(&(*dst)->_scheduler);
}

static void set_req_body_state(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, enum en_vhttp_req_body_state_t new_state)
{
    assert(stream->req_body.state < new_state); /* use `<` instead of `<=` as we think we only use the function that way, and
                                                 * setting CLOSE_DELIVERED twice causes unnecessary decrements */
    switch (new_state) {
    case vhttp_HTTP2_REQ_BODY_NONE:
        vhttp_fatal("invalid state");
        break;
    case vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED:
        assert(stream->req.proceed_req == NULL);
        if (stream->req_body.streamed) {
            conn->num_streams._req_streaming_in_progress--;
            if (stream->req.is_tunnel_req)
                conn->num_streams.tunnel--;
        }
        break;
    default:
        break;
    }
    stream->req_body.state = new_state;
}

void vhttp_http2_conn_unregister_stream(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    vhttp_http2_conn_preserve_stream_scheduler(conn, stream);

    khiter_t iter = kh_get(vhttp_http2_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(vhttp_http2_stream_t, conn->streams, iter);

    if (stream->req_body.state != vhttp_HTTP2_REQ_BODY_NONE && stream->req_body.state < vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED) {
        stream->req.proceed_req = NULL;
        set_req_body_state(conn, stream, vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED);
    }

    if (stream->blocked_by_server)
        vhttp_http2_stream_set_blocked_by_server(conn, stream, 0);

    /* Decrement reset_budget if the stream was reset by peer, otherwise increment. By doing so, we penalize connections that
     * generate resets for >50% of requests. */
    if (stream->reset_by_peer) {
        if (conn->dos_mitigation.reset_budget > 0)
            --conn->dos_mitigation.reset_budget;
    } else {
        if (conn->dos_mitigation.reset_budget < conn->super.ctx->globalconf->http2.max_concurrent_requests_per_connection)
            ++conn->dos_mitigation.reset_budget;
    }

    switch (stream->state) {
    case vhttp_HTTP2_STREAM_STATE_RECV_BODY:
        if (vhttp_linklist_is_linked(&stream->_link))
            vhttp_linklist_unlink(&stream->_link);
    /* fallthru */
    case vhttp_HTTP2_STREAM_STATE_IDLE:
    case vhttp_HTTP2_STREAM_STATE_RECV_HEADERS:
        assert(!vhttp_linklist_is_linked(&stream->_link));
        break;
    case vhttp_HTTP2_STREAM_STATE_REQ_PENDING:
        assert(vhttp_linklist_is_linked(&stream->_link));
        vhttp_linklist_unlink(&stream->_link);
        break;
    case vhttp_HTTP2_STREAM_STATE_SEND_HEADERS:
    case vhttp_HTTP2_STREAM_STATE_SEND_BODY:
    case vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
    case vhttp_HTTP2_STREAM_STATE_END_STREAM:
        if (vhttp_linklist_is_linked(&stream->_link))
            vhttp_linklist_unlink(&stream->_link);
        break;
    }
    if (stream->state != vhttp_HTTP2_STREAM_STATE_END_STREAM)
        vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_END_STREAM);

    if (conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING) {
        run_pending_requests(conn);
        update_idle_timeout(conn);
    }
}

void close_connection_now(vhttp_http2_conn_t *conn)
{
    /* mark as is_closing here to prevent sending any more frames */
    conn->state = vhttp_HTTP2_CONN_STATE_IS_CLOSING;

    vhttp_http2_stream_t *stream;

    assert(!vhttp_timer_is_linked(&conn->_write.timeout_entry));

    kh_foreach_value(conn->streams, stream, { vhttp_http2_stream_close(conn, stream); });

    assert(conn->num_streams.pull.open == 0);
    assert(conn->num_streams.pull.half_closed == 0);
    assert(conn->num_streams.pull.send_body == 0);
    assert(conn->num_streams.push.half_closed == 0);
    assert(conn->num_streams.push.send_body == 0);
    assert(conn->num_streams.priority.open == 0);
    assert(conn->num_streams.blocked_by_server == 0);
    assert(conn->num_streams._req_streaming_in_progress == 0);
    assert(conn->num_streams.tunnel == 0);
    kh_destroy(vhttp_http2_stream_t, conn->streams);
    assert(conn->_http1_req_input == NULL);
    vhttp_hpack_dispose_header_table(&conn->_input_header_table);
    vhttp_hpack_dispose_header_table(&conn->_output_header_table);
    assert(vhttp_linklist_is_empty(&conn->_pending_reqs));
    vhttp_timer_unlink(&conn->_timeout_entry);

    if (vhttp_timer_is_linked(&conn->_graceful_shutdown_timeout))
        vhttp_timer_unlink(&conn->_graceful_shutdown_timeout);

    if (vhttp_timer_is_linked(&conn->dos_mitigation.process_delay))
        vhttp_timer_unlink(&conn->dos_mitigation.process_delay);

    vhttp_buffer_dispose(&conn->_write.buf);
    if (conn->_write.buf_in_flight != NULL)
        vhttp_buffer_dispose(&conn->_write.buf_in_flight);
    {
        size_t i;
        for (i = 0; i < sizeof(conn->_recently_closed_streams.streams) / sizeof(conn->_recently_closed_streams.streams[0]); ++i) {
            vhttp_http2_stream_t *closed_stream = conn->_recently_closed_streams.streams[i];
            if (closed_stream == NULL)
                break;
            assert(vhttp_http2_scheduler_is_open(&closed_stream->_scheduler));
            vhttp_http2_scheduler_close(&closed_stream->_scheduler);
            free(closed_stream);
        }
    }
    vhttp_http2_scheduler_dispose(&conn->scheduler);
    assert(vhttp_linklist_is_empty(&conn->_write.streams_to_proceed));
    assert(!vhttp_timer_is_linked(&conn->_write.timeout_entry));
    if (conn->_headers_unparsed != NULL)
        vhttp_buffer_dispose(&conn->_headers_unparsed);
    if (conn->push_memo != NULL)
        vhttp_cache_destroy(conn->push_memo);
    if (conn->casper != NULL)
        vhttp_http2_casper_destroy(conn->casper);

    if (conn->sock != NULL)
        vhttp_socket_close(conn->sock);

    vhttp_destroy_connection(&conn->super);
}

int close_connection(vhttp_http2_conn_t *conn)
{
    conn->state = vhttp_HTTP2_CONN_STATE_IS_CLOSING;

    if (conn->_write.buf_in_flight != NULL || vhttp_timer_is_linked(&conn->_write.timeout_entry)) {
        /* there is a pending write, let on_write_complete actually close the connection */
    } else {
        close_connection_now(conn);
        return -1;
    }
    return 0;
}

static void stream_send_error(vhttp_http2_conn_t *conn, uint32_t stream_id, int errnum)
{
    assert(stream_id != 0);
    assert(conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING);

    conn->super.ctx->http2.events.protocol_level_errors[-errnum]++;

    vhttp_http2_encode_rst_stream_frame(&conn->_write.buf, stream_id, -errnum);
    vhttp_http2_conn_request_write(conn);
}

static void request_gathered_write(vhttp_http2_conn_t *conn)
{
    assert(conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING);
    if (!vhttp_socket_is_writing(conn->sock) && !vhttp_timer_is_linked(&conn->_write.timeout_entry)) {
        vhttp_timer_link(conn->super.ctx->loop, 0, &conn->_write.timeout_entry);
    }
}

static int update_stream_output_window(vhttp_http2_stream_t *stream, ssize_t delta)
{
    ssize_t cur = vhttp_http2_window_get_avail(&stream->output_window);
    if (vhttp_http2_window_update(&stream->output_window, delta) != 0)
        return -1;
    if (cur <= 0 && vhttp_http2_window_get_avail(&stream->output_window) > 0 &&
        (vhttp_http2_stream_has_pending_data(stream) || stream->state == vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL)) {
        assert(!vhttp_linklist_is_linked(&stream->_link));
        vhttp_http2_scheduler_activate(&stream->_scheduler);
    }
    return 0;
}

static void write_streaming_body(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    int is_end_stream = 0;

    assert(stream->req.entity.base == NULL);

    /* check state as well as update */
    switch (stream->req_body.state) {
    case vhttp_HTTP2_REQ_BODY_OPEN_BEFORE_FIRST_FRAME:
    case vhttp_HTTP2_REQ_BODY_OPEN:
        assert(stream->req_body.buf->size != 0);
        break;
    case vhttp_HTTP2_REQ_BODY_CLOSE_QUEUED:
        stream->req.proceed_req = NULL;
        set_req_body_state(conn, stream, vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED);
        is_end_stream = 1;
        break;
    default:
        vhttp_fatal("unexpected req_body.state");
        break;
    }

    /* invoke write_req */
    stream->req.entity = vhttp_iovec_init(stream->req_body.buf->bytes, stream->req_body.buf->size);
    if (stream->req.write_req.cb(stream->req.write_req.ctx, is_end_stream) != 0) {
        stream_send_error(conn, stream->stream_id, vhttp_HTTP2_ERROR_STREAM_CLOSED);
        vhttp_http2_stream_reset(conn, stream);
        return;
    }

    /* close the H2 stream if both sides are done */
    if (stream->req_body.state == vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED && stream->state == vhttp_HTTP2_STREAM_STATE_END_STREAM)
        vhttp_http2_stream_close(conn, stream);
}

static void handle_request_body_chunk(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, vhttp_iovec_t payload, int is_end_stream)
{
    int is_first = 0;

    switch (stream->req_body.state) {
    case vhttp_HTTP2_REQ_BODY_OPEN_BEFORE_FIRST_FRAME:
        is_first = 1;
        set_req_body_state(conn, stream, vhttp_HTTP2_REQ_BODY_OPEN);
        break;
    case vhttp_HTTP2_REQ_BODY_OPEN:
        break;
    default:
        vhttp_fatal("unexpected req_body.state");
        break;
    }

    stream->req.req_body_bytes_received += payload.len;

    /* check size */
    if (stream->req.req_body_bytes_received > conn->super.ctx->globalconf->max_request_entity_size) {
        stream_send_error(conn, stream->stream_id, vhttp_HTTP2_ERROR_REFUSED_STREAM);
        vhttp_http2_stream_reset(conn, stream);
        return;
    }
    if (stream->req.content_length != SIZE_MAX) {
        size_t received = stream->req.req_body_bytes_received, cl = stream->req.content_length;
        if (is_end_stream ? (received != cl) : (received > cl)) {
            stream_send_error(conn, stream->stream_id, vhttp_HTTP2_ERROR_PROTOCOL);
            vhttp_http2_stream_reset(conn, stream);
            return;
        }
    }

    /* update timer */
    if (!stream->blocked_by_server)
        vhttp_http2_stream_set_blocked_by_server(conn, stream, 1);

    /* just reset the stream if the request is to be disregarded */
    if (reset_stream_if_disregarded(conn, stream))
        return;

    /* update state, buffer the data */
    int req_queued = stream->req.proceed_req != NULL;
    if (is_end_stream) {
        if (stream->state < vhttp_HTTP2_STREAM_STATE_REQ_PENDING) {
            vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_REQ_PENDING);
            if (stream->req.process_called)
                vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_SEND_HEADERS);
        }
        if (stream->req.write_req.cb != NULL) {
            set_req_body_state(conn, stream, vhttp_HTTP2_REQ_BODY_CLOSE_QUEUED);
        } else {
            stream->req.proceed_req = NULL;
            set_req_body_state(conn, stream, vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED);
        }
    }
    vhttp_buffer_append(&stream->req_body.buf, payload.base, payload.len);

    /* if in request streaming mode: either submit the chunk or just keep it, and return */
    if (stream->req_body.streamed) {
        if (stream->req.write_req.cb != NULL) {
            if (stream->req.entity.base == NULL)
                write_streaming_body(conn, stream);
        } else {
            stream->req.entity = vhttp_iovec_init(stream->req_body.buf->bytes, stream->req_body.buf->size);
        }
        return;
    }

    /* not (yet) in streaming mode */
    stream->req.entity = vhttp_iovec_init(stream->req_body.buf->bytes, stream->req_body.buf->size);

    /* when receiving first DATA frame... */
    if (is_first && !is_end_stream) {
        /* trigger request streaming mode if possible */
        if (vhttp_req_can_stream_request(&stream->req)) {
            stream->req.proceed_req = proceed_request;
            execute_or_enqueue_request_core(conn, stream);
            return;
        }
        /* or, run in non-streaming mode (TODO elect input streams one by one for non-streaming case as well?) */
        update_stream_input_window(conn, stream,
                                   conn->super.ctx->globalconf->http2.active_stream_window_size -
                                       vhttp_HTTP2_SETTINGS_HOST_STREAM_INITIAL_WINDOW_SIZE);
    }

    /* run or queue the request when all input is available (and if the request has not been queued for streaming processing) */
    if (is_end_stream && !req_queued)
        execute_or_enqueue_request(conn, stream);
}

static int send_invalid_request_error(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, const char *err_desc)
{
    /* fast forward the stream's state so that we can start sending the response */
    vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_REQ_PENDING);
    vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_SEND_HEADERS);
    vhttp_send_error_400(&stream->req, "Invalid Request", err_desc, 0);
    return 0;
}

static int handle_incoming_request(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, const uint8_t *src, size_t len,
                                   const char **err_desc)
{
    int ret, header_exists_map = 0;
    vhttp_iovec_t expect = vhttp_iovec_init(NULL, 0);

    assert(stream->state == vhttp_HTTP2_STREAM_STATE_RECV_HEADERS);

    if ((ret = vhttp_hpack_parse_request(&stream->req.pool, vhttp_hpack_decode_header, &conn->_input_header_table,
                                       &stream->req.input.method, &stream->req.input.scheme, &stream->req.input.authority,
                                       &stream->req.input.path, &stream->req.upgrade, &stream->req.headers, &header_exists_map,
                                       &stream->req.content_length, &expect, &stream->cache_digests, NULL, src, len, err_desc)) !=
        0) {
        /* all errors except invalid-header-char are connection errors */
        if (ret != vhttp_HTTP2_ERROR_INVALID_HEADER_CHAR)
            return ret;
    }

    vhttp_probe_log_request(&stream->req, stream->stream_id);

    /* fixup the scheme so that it would never be a NULL pointer (note: checks below are done using `header_exists_map`) */
    if (stream->req.input.scheme == NULL)
        stream->req.input.scheme = conn->sock->ssl != NULL ? &vhttp_URL_SCHEME_HTTPS : &vhttp_URL_SCHEME_HTTP;

    int is_connect, must_exist_map, may_exist_map;
    if (vhttp_memis(stream->req.input.method.base, stream->req.input.method.len, vhttp_STRLIT("CONNECT"))) {
        is_connect = 1;
        must_exist_map = vhttp_HPACK_PARSE_HEADERS_METHOD_EXISTS | vhttp_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS;
        may_exist_map = 0;
        /* extended connect looks like an ordinary request plus an upgrade token (:protocol) */
        if ((header_exists_map & vhttp_HPACK_PARSE_HEADERS_PROTOCOL_EXISTS) != 0)
            must_exist_map |= vhttp_HPACK_PARSE_HEADERS_SCHEME_EXISTS | vhttp_HPACK_PARSE_HEADERS_PATH_EXISTS |
                              vhttp_HPACK_PARSE_HEADERS_PROTOCOL_EXISTS;
    } else if (vhttp_memis(stream->req.input.method.base, stream->req.input.method.len, vhttp_STRLIT("CONNECT-UDP"))) {
        /* Handling of masque draft-03. Method is CONNECT-UDP and :protocol is not used, so we set `:protocol` to "connect-udp" to
         * make it look like an upgrade. The method is preserved and can be used to distinguish between RFC 9298 version which uses
         * "CONNECT". The draft requires "masque" in `:scheme` but we need to support clients that put "https" there instead. */
        if (!((header_exists_map & vhttp_HPACK_PARSE_HEADERS_PROTOCOL_EXISTS) == 0 &&
              vhttp_memis(stream->req.input.path.base, stream->req.input.path.len, vhttp_STRLIT("/")))) {
            ret = vhttp_HTTP2_ERROR_PROTOCOL;
            goto SendRSTStream;
        }
        assert(stream->req.upgrade.base == NULL); /* otherwise PROTOCOL_EXISTS will be set */
        is_connect = 1;
        must_exist_map = vhttp_HPACK_PARSE_HEADERS_METHOD_EXISTS | vhttp_HPACK_PARSE_HEADERS_SCHEME_EXISTS |
                         vhttp_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS | vhttp_HPACK_PARSE_HEADERS_PATH_EXISTS;
        may_exist_map = 0;
    } else {
        /* normal request */
        is_connect = 0;
        must_exist_map =
            vhttp_HPACK_PARSE_HEADERS_METHOD_EXISTS | vhttp_HPACK_PARSE_HEADERS_SCHEME_EXISTS | vhttp_HPACK_PARSE_HEADERS_PATH_EXISTS;
        may_exist_map = vhttp_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS;
    }

    /* check that all MUST pseudo headers exist, and that there are no other pseudo headers than MUST or MAY */
    if (!((header_exists_map & must_exist_map) == must_exist_map && (header_exists_map & ~(must_exist_map | may_exist_map)) == 0)) {
        ret = vhttp_HTTP2_ERROR_PROTOCOL;
        goto SendRSTStream;
    }

    if (conn->num_streams.pull.open > conn->super.ctx->globalconf->http2.max_streams) {
        ret = vhttp_HTTP2_ERROR_REFUSED_STREAM;
        goto SendRSTStream;
    }

    /* send 400 if the request contains invalid header characters */
    if (ret != 0) {
        assert(ret == vhttp_HTTP2_ERROR_INVALID_HEADER_CHAR);
        return send_invalid_request_error(conn, stream, *err_desc);
    }

    /* special handling of CONNECT method */
    if (is_connect) {
        /* reject the request if content-length is specified or if the stream has been closed */
        if (stream->req.content_length != SIZE_MAX || stream->req_body.buf == NULL)
            return send_invalid_request_error(conn, stream, "Invalid CONNECT request");
        /* handle the request */
        stream->req.is_tunnel_req = 1;
        stream->req.entity = vhttp_iovec_init("", 0); /* setting to non-NULL pointer indicates the presence of HTTP payload */
        stream->req.proceed_req = proceed_request;
        vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_RECV_BODY);
        set_req_body_state(conn, stream, vhttp_HTTP2_REQ_BODY_OPEN);
        process_request(conn, stream);
        return 0;
    }

    /* handle expect: 100-continue */
    if (expect.base != NULL) {
        if (!vhttp_lcstris(expect.base, expect.len, vhttp_STRLIT("100-continue"))) {
            vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_REQ_PENDING);
            vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_SEND_HEADERS);
            vhttp_send_error_417(&stream->req, "Expectation Failed", "unknown expectation", 0);
            return 0;
        }
        stream->req.res.status = 100;
        vhttp_send_informational(&stream->req);
    }

    /* handle the request */
    if (stream->req_body.buf == NULL) {
        execute_or_enqueue_request(conn, stream);
    } else {
        vhttp_http2_stream_set_state(conn, stream, vhttp_HTTP2_STREAM_STATE_RECV_BODY);
        set_req_body_state(conn, stream, vhttp_HTTP2_REQ_BODY_OPEN_BEFORE_FIRST_FRAME);
    }
    return 0;

SendRSTStream:
    stream_send_error(conn, stream->stream_id, ret);
    vhttp_http2_stream_reset(conn, stream);
    return 0;
}

static int handle_trailing_headers(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, const uint8_t *src, size_t len,
                                   const char **err_desc)
{
    size_t dummy_content_length;
    vhttp_iovec_t dummy_expect = vhttp_iovec_init(NULL, 0);
    int ret;

    if ((ret = vhttp_hpack_parse_request(&stream->req.pool, vhttp_hpack_decode_header, &conn->_input_header_table, NULL, NULL, NULL,
                                       NULL, NULL, &stream->req.headers, NULL, &dummy_content_length, &dummy_expect, NULL, NULL,
                                       src, len, err_desc)) != 0)
        return ret;
    handle_request_body_chunk(conn, stream, vhttp_iovec_init(NULL, 0), 1);
    return 0;
}

static ssize_t expect_continuation_of_headers(vhttp_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    vhttp_http2_frame_t frame;
    ssize_t ret;
    vhttp_http2_stream_t *stream;
    int hret;

    if ((ret = vhttp_http2_decode_frame(&frame, src, len, vhttp_HTTP2_SETTINGS_HOST_MAX_FRAME_SIZE, err_desc)) < 0)
        return ret;
    if (frame.type != vhttp_HTTP2_FRAME_TYPE_CONTINUATION) {
        *err_desc = "expected CONTINUATION frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    if ((stream = vhttp_http2_conn_get_stream(conn, frame.stream_id)) == NULL ||
        !(stream->state == vhttp_HTTP2_STREAM_STATE_RECV_HEADERS || stream->state == vhttp_HTTP2_STREAM_STATE_RECV_BODY)) {
        *err_desc = "unexpected stream id in CONTINUATION frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    if (conn->_headers_unparsed->size + frame.length <= vhttp_MAX_REQLEN) {
        vhttp_buffer_reserve(&conn->_headers_unparsed, frame.length);
        memcpy(conn->_headers_unparsed->bytes + conn->_headers_unparsed->size, frame.payload, frame.length);
        conn->_headers_unparsed->size += frame.length;

        if ((frame.flags & vhttp_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
            conn->_read_expect = expect_default;
            if (stream->state == vhttp_HTTP2_STREAM_STATE_RECV_HEADERS) {
                hret = handle_incoming_request(conn, stream, (const uint8_t *)conn->_headers_unparsed->bytes,
                                               conn->_headers_unparsed->size, err_desc);
            } else {
                hret = handle_trailing_headers(conn, stream, (const uint8_t *)conn->_headers_unparsed->bytes,
                                               conn->_headers_unparsed->size, err_desc);
            }
            if (hret != 0)
                ret = hret;
            vhttp_buffer_dispose(&conn->_headers_unparsed);
            conn->_headers_unparsed = NULL;
        }
    } else {
        /* request is too large (TODO log) */
        stream_send_error(conn, stream->stream_id, vhttp_HTTP2_ERROR_REFUSED_STREAM);
        vhttp_http2_stream_reset(conn, stream);
    }

    return ret;
}

static void send_window_update(vhttp_http2_conn_t *conn, uint32_t stream_id, vhttp_http2_window_t *window, size_t delta)
{
    assert(delta <= INT32_MAX);
    vhttp_http2_encode_window_update_frame(&conn->_write.buf, stream_id, (int32_t)delta);
    vhttp_http2_conn_request_write(conn);
    vhttp_http2_window_update(window, delta);
}

void update_stream_input_window(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, size_t delta)
{
    stream->input_window.bytes_unnotified += delta;
    if (stream->input_window.bytes_unnotified >= vhttp_http2_window_get_avail(&stream->input_window.window)) {
        send_window_update(conn, stream->stream_id, &stream->input_window.window, stream->input_window.bytes_unnotified);
        stream->input_window.bytes_unnotified = 0;
    }
}

static void set_priority(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream, const vhttp_http2_priority_t *priority,
                         int scheduler_is_open)
{
    vhttp_http2_scheduler_node_t *parent_sched = NULL;

    /* determine the parent */
    if (priority->dependency != 0) {
        size_t i;
        /* First look for "recently closed" stream priorities.
         * This includes not only actually closed streams but also streams whose priority was modified
         * by vhttp (e.g. through priority header).
         * By searching this list first, priority of a newly arrived stream can correctly refer to a priority
         * specified by client before. */
        for (i = 0; i < HTTP2_CLOSED_STREAM_PRIORITIES; i++) {
            if (conn->_recently_closed_streams.streams[i] &&
                conn->_recently_closed_streams.streams[i]->stream_id == priority->dependency) {
                parent_sched = &conn->_recently_closed_streams.streams[i]->_scheduler.node;
                break;
            }
        }
        if (parent_sched == NULL) {
            /* If the above search for recently closed streams did not succeed (either the parent was not closed
             * recently or modified priority), get the priority scheduler currently associated with the parent
             * stream.
             */
            vhttp_http2_stream_t *parent_stream = vhttp_http2_conn_get_stream(conn, priority->dependency);
            if (parent_stream != NULL) {
                parent_sched = &parent_stream->_scheduler.node;
            } else {
                /* A dependency on a stream that is not currently in the tree - such as a stream in the "idle" state - results in
                 * that stream being given a default priority. (RFC 7540 5.3.1) It is possible for a stream to become closed while
                 * prioritization information that creates a dependency on that stream is in transit. If a stream identified in a
                 * dependency has no associated priority information, then the dependent stream is instead assigned a default
                 * priority. (RFC 7540 5.3.4)
                 */
                parent_sched = &conn->scheduler;
                priority = &vhttp_http2_default_priority;
            }
        } else if (conn->is_chromium_dependency_tree) {
            /* Parent stream was found in the recently closed streams.
             * There are two possible cases for this.
             * 1) the parent stream was actually closed recently
             * 2) the parent stream's priority was modified by vhttp (e.g. priority headers)
             * In case of 2), we might need to ignore the original dependency specified by the client,
             * if such a modification was a demotion (decreasing urgency/weight).
             *
             * This block handles case 2).
             */
            vhttp_http2_scheduler_openref_t *orig_parent_ref =
                vhttp_STRUCT_FROM_MEMBER(vhttp_http2_scheduler_openref_t, node, parent_sched);
            if (orig_parent_ref->weight < priority->weight || !priority->exclusive) {
                /* Turns out the client's dependency tree does not look like Chromium's */
                conn->is_chromium_dependency_tree = 0;
            } else {
                vhttp_http2_stream_t *current_parent_stream = vhttp_http2_conn_get_stream(conn, priority->dependency);
                if (current_parent_stream != NULL && orig_parent_ref->weight > current_parent_stream->_scheduler.weight &&
                    priority->exclusive) {
                    /* Parent stream was demoted as a result of reprioritization via priority header.
                     * In this case, search the new parent from the root so that this stream is handled before
                     * the parent originally specified by the client.
                     * This entire logic assumes Chromium-type dependency tree, thus guarded by
                     * `chromium_dependency_tree` */
                    parent_sched = vhttp_http2_scheduler_find_parent_by_weight(&conn->scheduler, priority->weight);
                    if (parent_sched == &stream->_scheduler.node) {
                        /* vhttp_http2_scheduler_find_parent_by_weight may return the current node itself.
                         * In such a case, correct parent should be the parent of the current node. */
                        parent_sched = &current_parent_stream->_scheduler.node;
                    }
                }
            }
        }
    } else {
        parent_sched = &conn->scheduler;
    }

    /* Verify if the client's dependency tree looks like Chromium's */
    if (priority->exclusive && conn->is_chromium_dependency_tree) {
        int parent_weight = 256;
        if (parent_sched->_parent != NULL && parent_sched->_parent->_parent != NULL) {
            vhttp_http2_scheduler_openref_t *parent_ref =
                vhttp_STRUCT_FROM_MEMBER(vhttp_http2_scheduler_openref_t, node, parent_sched->_parent);
            parent_weight = parent_ref->weight;
        }
        if (parent_weight < priority->weight) {
            /* Child's weight is bigger than parent's -- not Chromium */
            conn->is_chromium_dependency_tree = 0;
        }
    } else {
        /* Stream doesn't have the exclusive flag -- not Chromium */
        conn->is_chromium_dependency_tree = 0;
    }

    /* setup the scheduler */
    if (!scheduler_is_open) {
        vhttp_http2_scheduler_open(&stream->_scheduler, parent_sched, priority->weight, priority->exclusive);
    } else {
        vhttp_http2_scheduler_rebind(&stream->_scheduler, parent_sched, priority->weight, priority->exclusive);
    }
}

void proceed_request(vhttp_req_t *req, const char *errstr)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    vhttp_http2_conn_t *conn = (vhttp_http2_conn_t *)stream->req.conn;

    assert(stream->req_body.streamed);

    /* consume bytes */
    size_t written = stream->req.entity.len;
    vhttp_buffer_consume(&stream->req_body.buf, written);
    stream->req.entity = vhttp_iovec_init(NULL, 0);

    /* handle error */
    if (errstr != NULL) {
        stream->req.proceed_req = NULL;
        set_req_body_state(conn, stream, vhttp_HTTP2_REQ_BODY_CLOSE_DELIVERED);
        if (conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING) {
            /* Send error and close. State disposal is delayed so as to avoid freeing `req` within this function, which might
             * trigger the destruction of the generator being the caller. */
            stream_send_error(conn, stream->stream_id, vhttp_HTTP2_ERROR_STREAM_CLOSED);
            vhttp_http2_scheduler_deactivate(&stream->_scheduler);
            if (!vhttp_linklist_is_linked(&stream->_link))
                vhttp_linklist_insert(&conn->_write.streams_to_proceed, &stream->_link);
            vhttp_http2_stream_reset(conn, stream);
        }
        return;
    }

    switch (stream->req_body.state) {
    case vhttp_HTTP2_REQ_BODY_OPEN:
        update_stream_input_window(conn, stream, written);
        if (stream->blocked_by_server && vhttp_http2_window_get_avail(&stream->input_window.window) > 0) {
            vhttp_http2_stream_set_blocked_by_server(conn, stream, 0);
            update_idle_timeout(conn);
        }
        if (stream->req_body.buf->size != 0)
            write_streaming_body(conn, stream);
        break;
    case vhttp_HTTP2_REQ_BODY_CLOSE_QUEUED:
        assert(written != 0);
        write_streaming_body(conn, stream);
        break;
    default:
        vhttp_fatal("unexpected req_body_state");
    }
}

static int handle_data_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_data_payload_t payload;
    vhttp_http2_stream_t *stream;
    int ret;

    if ((ret = vhttp_http2_decode_data_payload(&payload, frame, err_desc)) != 0)
        return ret;

    /* update connection-level window */
    vhttp_http2_window_consume_window(&conn->_input_window, frame->length);
    if (vhttp_http2_window_get_avail(&conn->_input_window) <= vhttp_HTTP2_SETTINGS_HOST_CONNECTION_WINDOW_SIZE / 2)
        send_window_update(conn, 0, &conn->_input_window,
                           vhttp_HTTP2_SETTINGS_HOST_CONNECTION_WINDOW_SIZE - vhttp_http2_window_get_avail(&conn->_input_window));

    /* check state */
    if ((stream = vhttp_http2_conn_get_stream(conn, frame->stream_id)) == NULL) {
        if (frame->stream_id <= conn->pull_stream_ids.max_open) {
            stream_send_error(conn, frame->stream_id, vhttp_HTTP2_ERROR_STREAM_CLOSED);
            return 0;
        } else {
            *err_desc = "invalid DATA frame";
            return vhttp_HTTP2_ERROR_PROTOCOL;
        }
    }
    if (!(stream->req_body.state == vhttp_HTTP2_REQ_BODY_OPEN_BEFORE_FIRST_FRAME ||
          stream->req_body.state == vhttp_HTTP2_REQ_BODY_OPEN)) {
        stream_send_error(conn, frame->stream_id, vhttp_HTTP2_ERROR_STREAM_CLOSED);
        vhttp_http2_stream_reset(conn, stream);
        return 0;
    }

    /* update stream-level window (doing it here could end up in sending multiple WINDOW_UPDATE frames if the receive window is
     * fully-used, but no need to worry; in such case we'd be sending ACKs at a very fast rate anyways) */
    vhttp_http2_window_consume_window(&stream->input_window.window, frame->length);
    if (frame->length != payload.length)
        update_stream_input_window(conn, stream, frame->length - payload.length);

    /* actually handle the input */
    if (payload.length != 0 || (frame->flags & vhttp_HTTP2_FRAME_FLAG_END_STREAM) != 0)
        handle_request_body_chunk(conn, stream, vhttp_iovec_init(payload.data, payload.length),
                                  (frame->flags & vhttp_HTTP2_FRAME_FLAG_END_STREAM) != 0);

    return 0;
}

static int handle_headers_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_headers_payload_t payload;
    vhttp_http2_stream_t *stream;
    int ret;

    /* decode */
    if ((ret = vhttp_http2_decode_headers_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if ((frame->stream_id & 1) == 0) {
        *err_desc = "invalid stream id in HEADERS frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }
    if (frame->stream_id <= conn->pull_stream_ids.max_open) {
        if ((stream = vhttp_http2_conn_get_stream(conn, frame->stream_id)) == NULL) {
            *err_desc = "closed stream id in HEADERS frame";
            return vhttp_HTTP2_ERROR_STREAM_CLOSED;
        }
        if (!(stream->req_body.state == vhttp_HTTP2_REQ_BODY_OPEN_BEFORE_FIRST_FRAME ||
              stream->req_body.state == vhttp_HTTP2_REQ_BODY_OPEN)) {
            *err_desc = "invalid stream id in HEADERS frame";
            return vhttp_HTTP2_ERROR_PROTOCOL;
        }

        /* is a trailer */
        if (stream->req.is_tunnel_req) {
            *err_desc = "trailer cannot be used in a CONNECT request";
            return vhttp_HTTP2_ERROR_PROTOCOL;
        }
        if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_END_STREAM) == 0) {
            *err_desc = "trailing HEADERS frame MUST have END_STREAM flag set";
            return vhttp_HTTP2_ERROR_PROTOCOL;
        }
        if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_END_HEADERS) == 0)
            goto PREPARE_FOR_CONTINUATION;
        return handle_trailing_headers(conn, stream, payload.headers, payload.headers_len, err_desc);
    }
    if (frame->stream_id == payload.priority.dependency) {
        *err_desc = "stream cannot depend on itself";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    /* open or determine the stream and prepare */
    if ((stream = vhttp_http2_conn_get_stream(conn, frame->stream_id)) != NULL) {
        if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_PRIORITY) != 0) {
            set_priority(conn, stream, &payload.priority, 1);
            stream->received_priority = payload.priority;
        }
    } else {
        conn->received_any_request = 1;
        stream = vhttp_http2_stream_open(conn, frame->stream_id, NULL, &payload.priority);
        set_priority(conn, stream, &payload.priority, 0);
    }
    vhttp_http2_stream_prepare_for_request(conn, stream);

    /* setup container for request body if it is expected to arrive */
    if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_END_STREAM) == 0)
        vhttp_buffer_init(&stream->req_body.buf, &vhttp_socket_buffer_prototype);

    if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
        /* request headers are complete, handle it */
        return handle_incoming_request(conn, stream, payload.headers, payload.headers_len, err_desc);
    }

PREPARE_FOR_CONTINUATION:
    /* request is not complete, store in buffer */
    conn->_read_expect = expect_continuation_of_headers;
    vhttp_buffer_init(&conn->_headers_unparsed, &vhttp_socket_buffer_prototype);
    vhttp_buffer_reserve(&conn->_headers_unparsed, payload.headers_len);
    memcpy(conn->_headers_unparsed->bytes, payload.headers, payload.headers_len);
    conn->_headers_unparsed->size = payload.headers_len;
    return 0;
}

static int handle_priority_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_priority_t payload;
    vhttp_http2_stream_t *stream;
    int ret;

    if ((ret = vhttp_http2_decode_priority_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (frame->stream_id == payload.dependency) {
        *err_desc = "stream cannot depend on itself";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    if ((stream = vhttp_http2_conn_get_stream(conn, frame->stream_id)) != NULL) {
        stream->received_priority = payload;
        /* ignore priority changes to pushed streams with weight=257, since that is where we are trying to be smarter than the web
         * browsers
         */
        if (vhttp_http2_scheduler_get_weight(&stream->_scheduler) != 257)
            set_priority(conn, stream, &payload, 1);
    } else {
        if (vhttp_http2_stream_is_push(frame->stream_id)) {
            /* Ignore PRIORITY frames for closed or idle pushed streams */
            return 0;
        } else {
            /* Ignore PRIORITY frames for closed pull streams */
            if (frame->stream_id <= conn->pull_stream_ids.max_open)
                return 0;
        }
        if (conn->num_streams.priority.open >= conn->super.ctx->globalconf->http2.max_streams_for_priority) {
            *err_desc = "too many streams in idle/closed state";
            /* RFC 7540 10.5: An endpoint MAY treat activity that is suspicious as a connection error (Section 5.4.1) of type
             * ENHANCE_YOUR_CALM.
             */
            return vhttp_HTTP2_ERROR_ENHANCE_YOUR_CALM;
        }
        stream = vhttp_http2_stream_open(conn, frame->stream_id, NULL, &payload);
        set_priority(conn, stream, &payload, 0);
    }

    return 0;
}

static void resume_send(vhttp_http2_conn_t *conn)
{
    if (vhttp_http2_conn_get_buffer_window(conn) <= 0)
        return;
#if 0 /* TODO reenable this check for performance? */
    if (conn->scheduler.list.size == 0)
        return;
#endif
    request_gathered_write(conn);
}

static int handle_settings_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
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
        if (vhttp_timeval_is_null(&conn->timestamps.settings_acked_at) && !vhttp_timeval_is_null(&conn->timestamps.settings_sent_at)) {
            conn->timestamps.settings_acked_at = vhttp_gettimeofday(conn->super.ctx->loop);
        }
    } else {
        uint32_t prev_initial_window_size = conn->peer_settings.initial_window_size;
        int ret = vhttp_http2_update_peer_settings(&conn->peer_settings, frame->payload, frame->length, err_desc);
        if (ret != 0)
            return ret;
        { /* schedule ack */
            vhttp_iovec_t header_buf = vhttp_buffer_reserve(&conn->_write.buf, vhttp_HTTP2_FRAME_HEADER_SIZE);
            vhttp_http2_encode_frame_header((void *)header_buf.base, 0, vhttp_HTTP2_FRAME_TYPE_SETTINGS, vhttp_HTTP2_FRAME_FLAG_ACK, 0);
            conn->_write.buf->size += vhttp_HTTP2_FRAME_HEADER_SIZE;
            vhttp_http2_conn_request_write(conn);
        }
        /* apply the change to window size (to all the streams but not the connection, see 6.9.2 of draft-15) */
        if (prev_initial_window_size != conn->peer_settings.initial_window_size) {
            ssize_t delta = (int32_t)conn->peer_settings.initial_window_size - (int32_t)prev_initial_window_size;
            vhttp_http2_stream_t *stream;
            kh_foreach_value(conn->streams, stream, { update_stream_output_window(stream, delta); });
            resume_send(conn);
        }
    }

    return 0;
}

static int handle_window_update_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_window_update_payload_t payload;
    int ret, err_is_stream_level;

    if ((ret = vhttp_http2_decode_window_update_payload(&payload, frame, err_desc, &err_is_stream_level)) != 0) {
        if (err_is_stream_level) {
            vhttp_http2_stream_t *stream = vhttp_http2_conn_get_stream(conn, frame->stream_id);
            if (stream != NULL)
                vhttp_http2_stream_reset(conn, stream);
            stream_send_error(conn, frame->stream_id, ret);
            return 0;
        } else {
            return ret;
        }
    }

    if (frame->stream_id == 0) {
        if (vhttp_http2_window_update(&conn->_write.window, payload.window_size_increment) != 0) {
            *err_desc = "flow control window overflow";
            return vhttp_HTTP2_ERROR_FLOW_CONTROL;
        }
    } else if (!is_idle_stream_id(conn, frame->stream_id)) {
        vhttp_http2_stream_t *stream = vhttp_http2_conn_get_stream(conn, frame->stream_id);
        if (stream != NULL) {
            if (update_stream_output_window(stream, payload.window_size_increment) != 0) {
                vhttp_http2_stream_reset(conn, stream);
                stream_send_error(conn, frame->stream_id, vhttp_HTTP2_ERROR_FLOW_CONTROL);
                return 0;
            }
        }
    } else {
        *err_desc = "invalid stream id in WINDOW_UPDATE frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    resume_send(conn);

    return 0;
}

static int handle_goaway_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_goaway_payload_t payload;
    int ret;

    if ((ret = vhttp_http2_decode_goaway_payload(&payload, frame, err_desc)) != 0)
        return ret;

    /* stop opening new push streams hereafter */
    conn->push_stream_ids.max_open = 0x7ffffffe;

    return 0;
}

static int handle_ping_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_ping_payload_t payload;
    int ret;

    if ((ret = vhttp_http2_decode_ping_payload(&payload, frame, err_desc)) != 0)
        return ret;

    if ((frame->flags & vhttp_HTTP2_FRAME_FLAG_ACK) == 0) {
        vhttp_http2_encode_ping_frame(&conn->_write.buf, 1, payload.data);
        vhttp_http2_conn_request_write(conn);
    }

    return 0;
}

static int handle_rst_stream_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    vhttp_http2_rst_stream_payload_t payload;
    vhttp_http2_stream_t *stream;
    int ret;

    if ((ret = vhttp_http2_decode_rst_stream_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (is_idle_stream_id(conn, frame->stream_id)) {
        *err_desc = "unexpected stream id in RST_STREAM frame";
        return vhttp_HTTP2_ERROR_PROTOCOL;
    }

    if ((stream = vhttp_http2_conn_get_stream(conn, frame->stream_id)) == NULL)
        return 0;

    /* reset the stream */
    stream->reset_by_peer = 1;
    vhttp_http2_stream_reset(conn, stream);

    /* setup process delay if we've just ran out of reset budget */
    if (conn->dos_mitigation.reset_budget == 0 && conn->super.ctx->globalconf->http2.dos_delay != 0 &&
        !vhttp_timer_is_linked(&conn->dos_mitigation.process_delay))
        vhttp_timer_link(conn->super.ctx->loop, conn->super.ctx->globalconf->http2.dos_delay, &conn->dos_mitigation.process_delay);

    /* TODO log */

    return 0;
}

static int handle_push_promise_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received PUSH_PROMISE frame";
    return vhttp_HTTP2_ERROR_PROTOCOL;
}

static int handle_invalid_continuation_frame(vhttp_http2_conn_t *conn, vhttp_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received invalid CONTINUATION frame";
    return vhttp_HTTP2_ERROR_PROTOCOL;
}

ssize_t expect_default(vhttp_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    vhttp_http2_frame_t frame;
    ssize_t ret;
    static int (*FRAME_HANDLERS[])(vhttp_http2_conn_t * conn, vhttp_http2_frame_t * frame, const char **err_desc) = {
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

    if ((ret = vhttp_http2_decode_frame(&frame, src, len, vhttp_HTTP2_SETTINGS_HOST_MAX_FRAME_SIZE, err_desc)) < 0)
        return ret;

    if (frame.type < sizeof(FRAME_HANDLERS) / sizeof(FRAME_HANDLERS[0])) {
        int hret = FRAME_HANDLERS[frame.type](conn, &frame, err_desc);
        if (hret != 0)
            ret = hret;
    } else {
        vhttp_PROBE_CONN(H2_UNKNOWN_FRAME_TYPE, &conn->super, frame.type);
    }

    return ret;
}

static ssize_t expect_preface(vhttp_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    if (len < CONNECTION_PREFACE.len) {
        return vhttp_HTTP2_ERROR_INCOMPLETE;
    }
    if (memcmp(src, CONNECTION_PREFACE.base, CONNECTION_PREFACE.len) != 0) {
        return vhttp_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY;
    }

    {
        enqueue_server_preface(conn);
        if (conn->http2_origin_frame) {
            /* write origin frame */
            vhttp_http2_encode_origin_frame(&conn->_write.buf, *conn->http2_origin_frame);
        }
        if (vhttp_timeval_is_null(&conn->timestamps.settings_sent_at)) {
            conn->timestamps.settings_sent_at = vhttp_gettimeofday(conn->super.ctx->loop);
        }
        vhttp_http2_conn_request_write(conn);
    }

    conn->_read_expect = expect_default;
    return CONNECTION_PREFACE.len;
}

static int parse_input(vhttp_http2_conn_t *conn)
{
    /* handle the input */
    while (conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING && conn->sock->input->size != 0) {
        /* process a frame */
        const char *err_desc = NULL;
        ssize_t ret = conn->_read_expect(conn, (uint8_t *)conn->sock->input->bytes, conn->sock->input->size, &err_desc);
        if (ret == vhttp_HTTP2_ERROR_INCOMPLETE) {
            break;
        } else if (ret < 0) {
            if (ret != vhttp_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY) {
                enqueue_goaway(conn, (int)ret,
                               err_desc != NULL ? (vhttp_iovec_t){(char *)err_desc, strlen(err_desc)} : (vhttp_iovec_t){NULL});
            }
            return close_connection(conn);
        }
        /* advance to the next frame */
        vhttp_buffer_consume(&conn->sock->input, ret);
    }
    return 0;
}

static void on_read(vhttp_socket_t *sock, const char *err)
{
    vhttp_http2_conn_t *conn = sock->data;

    if (err != NULL) {
        conn->super.ctx->http2.events.read_closed++;
        vhttp_socket_read_stop(conn->sock);
        close_connection(conn);
        return;
    }

    /* dispatch requests blocked by 425 when TLS handshake is complete */
    if (!vhttp_linklist_is_empty(&conn->early_data.blocked_streams)) {
        assert(conn->sock->ssl != NULL);
        if (!vhttp_socket_ssl_is_early_data(conn->sock)) {
            while (conn->early_data.blocked_streams.next != &conn->early_data.blocked_streams) {
                vhttp_http2_stream_t *stream =
                    vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, _link, conn->early_data.blocked_streams.next);
                vhttp_linklist_unlink(&stream->_link);
                if (!stream->blocked_by_server)
                    vhttp_http2_stream_set_blocked_by_server(conn, stream, 1);
                vhttp_replay_request(&stream->req);
            }
        }
    }

    if (parse_input(conn) != 0)
        return;
    update_idle_timeout(conn);

    /* write immediately, if there is no write in flight and if pending write exists */
    if (vhttp_timer_is_linked(&conn->_write.timeout_entry)) {
        vhttp_timer_unlink(&conn->_write.timeout_entry);
        do_emit_writereq(conn);
    }
}

static void on_upgrade_complete(void *_conn, vhttp_socket_t *sock, size_t reqsize)
{
    vhttp_http2_conn_t *conn = _conn;

    if (sock == NULL) {
        close_connection(conn);
        return;
    }

    conn->sock = sock;
    sock->data = conn;
    conn->_http1_req_input = sock->input;
    vhttp_buffer_init(&sock->input, &vhttp_socket_buffer_prototype);

    enqueue_server_preface(conn);
    vhttp_http2_conn_request_write(conn);

    /* setup inbound */
    vhttp_socket_read_start(conn->sock, on_read);

    /* handle the request */
    execute_or_enqueue_request(conn, vhttp_http2_conn_get_stream(conn, 1));

    if (conn->_http1_req_input->size > reqsize) {
        size_t remaining_bytes = conn->_http1_req_input->size - reqsize;
        vhttp_buffer_reserve(&sock->input, remaining_bytes);
        memcpy(sock->input->bytes, conn->_http1_req_input->bytes + reqsize, remaining_bytes);
        sock->input->size += remaining_bytes;
        on_read(conn->sock, NULL);
    }
}

static size_t bytes_in_buf(vhttp_http2_conn_t *conn)
{
    size_t size = conn->_write.buf->size;
    if (conn->_write.buf_in_flight != 0)
        size += conn->_write.buf_in_flight->size;
    return size;
}

void vhttp_http2_conn_request_write(vhttp_http2_conn_t *conn)
{
    if (conn->state == vhttp_HTTP2_CONN_STATE_IS_CLOSING)
        return;
    if (vhttp_socket_is_reading(conn->sock) && bytes_in_buf(conn) >= vhttp_HTTP2_DEFAULT_OUTBUF_SOFT_MAX_SIZE)
        vhttp_socket_read_stop(conn->sock);
    request_gathered_write(conn);
}

void vhttp_http2_conn_register_for_proceed_callback(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    vhttp_http2_conn_request_write(conn);

    if (vhttp_http2_stream_has_pending_data(stream) || stream->state >= vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL) {
        if (vhttp_http2_window_get_avail(&stream->output_window) > 0) {
            assert(!vhttp_linklist_is_linked(&stream->_link));
            vhttp_http2_scheduler_activate(&stream->_scheduler);
        }
    } else {
        vhttp_linklist_insert(&conn->_write.streams_to_proceed, &stream->_link);
    }
}

void vhttp_http2_conn_register_for_replay(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    if (conn->sock->ssl != NULL && vhttp_socket_ssl_is_early_data(conn->sock)) {
        vhttp_linklist_insert(&conn->early_data.blocked_streams, &stream->_link);
    } else {
        vhttp_replay_request_deferred(&stream->req);
    }
}

static void on_notify_write(vhttp_socket_t *sock, const char *err)
{
    vhttp_http2_conn_t *conn = sock->data;

    if (err != NULL) {
        close_connection_now(conn);
        return;
    }
    do_emit_writereq(conn);
}

static void on_write_complete(vhttp_socket_t *sock, const char *err)
{
    vhttp_http2_conn_t *conn = sock->data;

    assert(conn->_write.buf_in_flight != NULL);

    /* close by error if necessary */
    if (err != NULL) {
        conn->super.ctx->http2.events.write_closed++;
        close_connection_now(conn);
        return;
    }

    /* reset the other memory pool */
    vhttp_buffer_dispose(&conn->_write.buf_in_flight);
    assert(conn->_write.buf_in_flight == NULL);

    /* call the proceed callback of the streams that have been flushed (while unlinking them from the list) */
    if (conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING) {
        while (!vhttp_linklist_is_empty(&conn->_write.streams_to_proceed)) {
            vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, _link, conn->_write.streams_to_proceed.next);
            assert(!vhttp_http2_stream_has_pending_data(stream));
            vhttp_linklist_unlink(&stream->_link);
            vhttp_http2_stream_proceed(conn, stream);
        }
    }

    /* update the timeout now that the states have been updated */
    update_idle_timeout(conn);

    /* cancel the write callback if scheduled (as the generator may have scheduled a write just before this function gets called) */
    if (vhttp_timer_is_linked(&conn->_write.timeout_entry))
        vhttp_timer_unlink(&conn->_write.timeout_entry);

    if (conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING) {
        if (!vhttp_socket_is_reading(conn->sock) && bytes_in_buf(conn) < vhttp_HTTP2_DEFAULT_OUTBUF_SOFT_MAX_SIZE)
            vhttp_socket_read_start(conn->sock, on_read);
    }

#if !vhttp_USE_LIBUV
    if (conn->state == vhttp_HTTP2_CONN_STATE_OPEN) {
        if (conn->_write.buf->size != 0 || vhttp_http2_scheduler_is_active(&conn->scheduler))
            vhttp_socket_notify_write(sock, on_notify_write);
        return;
    }
#endif

    /* write more, if possible */
    do_emit_writereq(conn);
}

static int emit_writereq_of_openref(vhttp_http2_scheduler_openref_t *ref, int *still_is_active, void *cb_arg)
{
    vhttp_http2_conn_t *conn = cb_arg;
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, _scheduler, ref);

    assert(vhttp_http2_stream_has_pending_data(stream) || stream->state >= vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL);

    *still_is_active = 0;

    vhttp_http2_stream_send_pending_data(conn, stream);
    if (vhttp_http2_stream_has_pending_data(stream) || stream->state == vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL) {
        if (vhttp_http2_window_get_avail(&stream->output_window) <= 0) {
            /* is blocked */
        } else {
            *still_is_active = 1;
        }
    } else {
        if (stream->state == vhttp_HTTP2_STREAM_STATE_END_STREAM) {
            vhttp_iovec_t server_timing;
            if (stream->req.send_server_timing &&
                (server_timing = vhttp_build_server_timing_trailer(&stream->req, NULL, 0, NULL, 0)).len != 0) {
                static const vhttp_iovec_t name = {vhttp_STRLIT("server-timing")};
                vhttp_vector_reserve(&stream->req.pool, &stream->req.res.trailers, stream->req.res.trailers.size + 1);
                stream->req.res.trailers.entries[stream->req.res.trailers.size++] =
                    (vhttp_header_t){(vhttp_iovec_t *)&name, NULL, server_timing};
            }
            if (stream->req.res.trailers.size != 0) {
                vhttp_hpack_flatten_trailers(&conn->_write.buf, &conn->_output_header_table, conn->peer_settings.header_table_size,
                                           stream->stream_id, conn->peer_settings.max_frame_size, stream->req.res.trailers.entries,
                                           stream->req.res.trailers.size);
            }
        }
        vhttp_linklist_insert(&conn->_write.streams_to_proceed, &stream->_link);
    }

    return vhttp_http2_conn_get_buffer_window(conn) > 0 ? 0 : -1;
}

void do_emit_writereq(vhttp_http2_conn_t *conn)
{
    assert(conn->_write.buf_in_flight == NULL);

    /* push DATA frames */
    if (conn->state < vhttp_HTTP2_CONN_STATE_IS_CLOSING && vhttp_http2_conn_get_buffer_window(conn) > 0)
        vhttp_http2_scheduler_run(&conn->scheduler, emit_writereq_of_openref, conn);

    if (conn->_write.buf->size != 0) {
        /* write and wait for completion */
        vhttp_iovec_t buf = {conn->_write.buf->bytes, conn->_write.buf->size};
        vhttp_socket_write(conn->sock, &buf, 1, on_write_complete);
        conn->_write.buf_in_flight = conn->_write.buf;
        vhttp_buffer_init(&conn->_write.buf, &vhttp_http2_wbuf_buffer_prototype);
        vhttp_timer_unlink(&conn->_timeout_entry);
        vhttp_timer_link(conn->super.ctx->loop, vhttp_HTTP2_DEFAULT_OUTBUF_WRITE_TIMEOUT, &conn->_timeout_entry);
    }

    /* close the connection if necessary */
    switch (conn->state) {
    case vhttp_HTTP2_CONN_STATE_OPEN:
        break;
    case vhttp_HTTP2_CONN_STATE_HALF_CLOSED:
        if (conn->num_streams.pull.open + conn->num_streams.push.open != 0)
            break;
        conn->state = vhttp_HTTP2_CONN_STATE_IS_CLOSING;
    /* fall-thru */
    case vhttp_HTTP2_CONN_STATE_IS_CLOSING:
        close_connection(conn);
        break;
    }
}

static void emit_writereq(vhttp_timer_t *entry)
{
    vhttp_http2_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_conn_t, _write.timeout_entry, entry);

    do_emit_writereq(conn);
}

static socklen_t get_sockname(vhttp_conn_t *_conn, struct sockaddr *sa)
{
    vhttp_http2_conn_t *conn = (void *)_conn;
    return vhttp_socket_getsockname(conn->sock, sa);
}

static socklen_t get_peername(vhttp_conn_t *_conn, struct sockaddr *sa)
{
    vhttp_http2_conn_t *conn = (void *)_conn;
    return vhttp_socket_getpeername(conn->sock, sa);
}

static ptls_t *get_ptls(vhttp_conn_t *_conn)
{
    struct st_vhttp_http2_conn_t *conn = (void *)_conn;
    assert(conn->sock != NULL && "it never becomes NULL, right?");
    return vhttp_socket_get_ptls(conn->sock);
}

static int skip_tracing(vhttp_conn_t *_conn)
{
    struct st_vhttp_http2_conn_t *conn = (void *)_conn;
    assert(conn->sock != NULL && "it never becomes NULL, right?");
    return vhttp_socket_skip_tracing(conn->sock);
}

static uint64_t get_req_id(vhttp_req_t *req)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    return stream->stream_id;
}

static int64_t get_rtt(vhttp_conn_t *_conn)
{
    struct st_vhttp_http2_conn_t *conn = (void *)_conn;
    if (!vhttp_timeval_is_null(&conn->timestamps.settings_sent_at) && !vhttp_timeval_is_null(&conn->timestamps.settings_acked_at)) {
        return vhttp_timeval_subtract(&conn->timestamps.settings_sent_at, &conn->timestamps.settings_acked_at);
    } else {
        return -1;
    }
}

#define DEFINE_LOGGER(name)                                                                                                        \
    static vhttp_iovec_t log_##name(vhttp_req_t *req)                                                                                  \
    {                                                                                                                              \
        vhttp_http2_conn_t *conn = (void *)req->conn;                                                                                \
        return vhttp_socket_log_##name(conn->sock, &req->pool);                                                                      \
    }
DEFINE_LOGGER(tcp_congestion_controller)
DEFINE_LOGGER(tcp_delivery_rate)
DEFINE_LOGGER(ssl_protocol_version)
DEFINE_LOGGER(ssl_session_reused)
DEFINE_LOGGER(ssl_cipher)
DEFINE_LOGGER(ssl_cipher_bits)
DEFINE_LOGGER(ssl_session_id)
DEFINE_LOGGER(ssl_server_name)
DEFINE_LOGGER(ssl_negotiated_protocol)
DEFINE_LOGGER(ssl_ech_config_id)
DEFINE_LOGGER(ssl_ech_kem)
DEFINE_LOGGER(ssl_ech_cipher)
DEFINE_LOGGER(ssl_ech_cipher_bits)
DEFINE_LOGGER(ssl_backend)
#undef DEFINE_LOGGER

static vhttp_iovec_t log_stream_id(vhttp_req_t *req)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    char *s = vhttp_mem_alloc_pool(&stream->req.pool, *s, sizeof(vhttp_UINT32_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%" PRIu32, stream->stream_id);
    return vhttp_iovec_init(s, len);
}

static vhttp_iovec_t log_priority_received(vhttp_req_t *req)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    char *s = vhttp_mem_alloc_pool(&stream->req.pool, *s, sizeof("1:" vhttp_UINT32_LONGEST_STR ":" vhttp_UINT16_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%c:%" PRIu32 ":%" PRIu16, stream->received_priority.exclusive ? '1' : '0',
                                 stream->received_priority.dependency, stream->received_priority.weight);
    return vhttp_iovec_init(s, len);
}

static vhttp_iovec_t log_priority_received_exclusive(vhttp_req_t *req)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    return vhttp_iovec_init(stream->received_priority.exclusive ? "1" : "0", 1);
}

static vhttp_iovec_t log_priority_received_parent(vhttp_req_t *req)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    char *s = vhttp_mem_alloc_pool(&stream->req.pool, *s, sizeof(vhttp_UINT32_LONGEST_STR));
    size_t len = sprintf(s, "%" PRIu32, stream->received_priority.dependency);
    return vhttp_iovec_init(s, len);
}

static vhttp_iovec_t log_priority_received_weight(vhttp_req_t *req)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    char *s = vhttp_mem_alloc_pool(&stream->req.pool, *s, sizeof(vhttp_UINT16_LONGEST_STR));
    size_t len = sprintf(s, "%" PRIu16, stream->received_priority.weight);
    return vhttp_iovec_init(s, len);
}

static uint32_t get_parent_stream_id(vhttp_http2_conn_t *conn, vhttp_http2_stream_t *stream)
{
    vhttp_http2_scheduler_node_t *parent_sched = vhttp_http2_scheduler_get_parent(&stream->_scheduler);
    if (parent_sched == &conn->scheduler) {
        return 0;
    } else {
        vhttp_http2_stream_t *parent_stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, _scheduler, parent_sched);
        return parent_stream->stream_id;
    }
}

static vhttp_iovec_t log_priority_actual(vhttp_req_t *req)
{
    vhttp_http2_conn_t *conn = (void *)req->conn;
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    char *s = vhttp_mem_alloc_pool(&stream->req.pool, *s, sizeof(vhttp_UINT32_LONGEST_STR ":" vhttp_UINT16_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%" PRIu32 ":%" PRIu16, get_parent_stream_id(conn, stream),
                                 vhttp_http2_scheduler_get_weight(&stream->_scheduler));
    return vhttp_iovec_init(s, len);
}

static vhttp_iovec_t log_priority_actual_parent(vhttp_req_t *req)
{
    vhttp_http2_conn_t *conn = (void *)req->conn;
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    char *s = vhttp_mem_alloc_pool(&stream->req.pool, *s, sizeof(vhttp_UINT32_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%" PRIu32, get_parent_stream_id(conn, stream));
    return vhttp_iovec_init(s, len);
}

static vhttp_iovec_t log_priority_actual_weight(vhttp_req_t *req)
{
    vhttp_http2_stream_t *stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, req);
    char *s = vhttp_mem_alloc_pool(&stream->req.pool, *s, sizeof(vhttp_UINT16_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%" PRIu16, vhttp_http2_scheduler_get_weight(&stream->_scheduler));
    return vhttp_iovec_init(s, len);
}

static void on_dos_process_delay(vhttp_timer_t *timer)
{
    vhttp_http2_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_conn_t, dos_mitigation.process_delay, timer);

    assert(!vhttp_timer_is_linked(&conn->dos_mitigation.process_delay));
    run_pending_requests(conn);
}

static vhttp_http2_conn_t *create_conn(vhttp_context_t *ctx, vhttp_hostconf_t **hosts, vhttp_socket_t *sock, struct timeval connected_at)
{
    static const vhttp_conn_callbacks_t callbacks = {
        .get_sockname = get_sockname,
        .get_peername = get_peername,
        .get_ptls = get_ptls,
        .skip_tracing = skip_tracing,
        .get_req_id = get_req_id,
        .push_path = push_path,
        .get_debug_state = vhttp_http2_get_debug_state,
        .close_idle_connection = close_idle_connection,
        .foreach_request = foreach_request,
        .request_shutdown = initiate_graceful_shutdown,
        .get_rtt = get_rtt,
        .log_ = {{
            .transport =
                {
                    .cc_name = log_tcp_congestion_controller,
                    .delivery_rate = log_tcp_delivery_rate,
                },
            .ssl =
                {
                    .protocol_version = log_ssl_protocol_version,
                    .session_reused = log_ssl_session_reused,
                    .cipher = log_ssl_cipher,
                    .cipher_bits = log_ssl_cipher_bits,
                    .session_id = log_ssl_session_id,
                    .server_name = log_ssl_server_name,
                    .negotiated_protocol = log_ssl_negotiated_protocol,
                    .ech_config_id = log_ssl_ech_config_id,
                    .ech_kem = log_ssl_ech_kem,
                    .ech_cipher = log_ssl_ech_cipher,
                    .ech_cipher_bits = log_ssl_ech_cipher_bits,
                    .backend = log_ssl_backend,
                },
            .http2 =
                {
                    .stream_id = log_stream_id,
                    .priority_received = log_priority_received,
                    .priority_received_exclusive = log_priority_received_exclusive,
                    .priority_received_parent = log_priority_received_parent,
                    .priority_received_weight = log_priority_received_weight,
                    .priority_actual = log_priority_actual,
                    .priority_actual_parent = log_priority_actual_parent,
                    .priority_actual_weight = log_priority_actual_weight,
                },
        }},
    };

    vhttp_http2_conn_t *conn = (void *)vhttp_create_connection(sizeof(*conn), ctx, hosts, connected_at, &callbacks);

    memset((char *)conn + sizeof(conn->super), 0, sizeof(*conn) - sizeof(conn->super));
    conn->sock = sock;
    conn->peer_settings = vhttp_HTTP2_SETTINGS_DEFAULT;
    conn->streams = kh_init(vhttp_http2_stream_t);
    vhttp_http2_scheduler_init(&conn->scheduler);
    conn->state = vhttp_HTTP2_CONN_STATE_OPEN;
    conn->_read_expect = expect_preface;
    conn->_input_header_table.hpack_capacity = conn->_input_header_table.hpack_max_capacity =
        vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size;
    vhttp_http2_window_init(&conn->_input_window, vhttp_HTTP2_SETTINGS_HOST_CONNECTION_WINDOW_SIZE);
    conn->_output_header_table.hpack_capacity = vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size;
    vhttp_linklist_init_anchor(&conn->_pending_reqs);
    vhttp_buffer_init(&conn->_write.buf, &vhttp_http2_wbuf_buffer_prototype);
    vhttp_linklist_init_anchor(&conn->_write.streams_to_proceed);
    conn->_write.timeout_entry.cb = emit_writereq;
    vhttp_http2_window_init(&conn->_write.window, conn->peer_settings.initial_window_size);
    vhttp_linklist_init_anchor(&conn->early_data.blocked_streams);
    conn->is_chromium_dependency_tree = 1; /* initially assume the client is Chromium until proven otherwise */
    conn->received_any_request = 0;
    conn->dos_mitigation.process_delay.cb = on_dos_process_delay;
    conn->dos_mitigation.reset_budget = conn->super.ctx->globalconf->http2.max_concurrent_requests_per_connection;

    return conn;
}

static int update_push_memo(vhttp_http2_conn_t *conn, vhttp_req_t *src_req, const char *abspath, size_t abspath_len)
{

    if (conn->push_memo == NULL)
        conn->push_memo = vhttp_cache_create(0, 1024, 1, NULL);

    /* uses the hash as the key */
    vhttp_cache_hashcode_t url_hash = vhttp_cache_calchash(src_req->input.scheme->name.base, src_req->input.scheme->name.len) ^
                                    vhttp_cache_calchash(src_req->input.authority.base, src_req->input.authority.len) ^
                                    vhttp_cache_calchash(abspath, abspath_len);
    return vhttp_cache_set(conn->push_memo, 0, vhttp_iovec_init(&url_hash, sizeof(url_hash)), url_hash, vhttp_iovec_init(NULL, 0));
}

static void push_path(vhttp_req_t *src_req, const char *abspath, size_t abspath_len, int is_critical)
{
    vhttp_http2_conn_t *conn = (void *)src_req->conn;
    vhttp_http2_stream_t *src_stream = vhttp_STRUCT_FROM_MEMBER(vhttp_http2_stream_t, req, src_req);

    /* RFC 7540 8.2.1: PUSH_PROMISE frames can be sent by the server in response to any client-initiated stream */
    if (vhttp_http2_stream_is_push(src_stream->stream_id))
        return;

    if (!src_stream->req.hostconf->http2.push_preload || !conn->peer_settings.enable_push ||
        conn->num_streams.push.open >= conn->peer_settings.max_concurrent_streams)
        return;

    if (conn->state >= vhttp_HTTP2_CONN_STATE_IS_CLOSING)
        return;
    if (conn->push_stream_ids.max_open >= 0x7ffffff0)
        return;
    if (!(vhttp_linklist_is_empty(&conn->_pending_reqs) && can_run_requests(conn)))
        return;

    if (vhttp_find_header(&src_stream->req.headers, vhttp_TOKEN_X_FORWARDED_FOR, -1) != -1)
        return;

    if (src_stream->cache_digests != NULL) {
        vhttp_iovec_t url = vhttp_concat(&src_stream->req.pool, src_stream->req.input.scheme->name, vhttp_iovec_init(vhttp_STRLIT("://")),
                                     src_stream->req.input.authority, vhttp_iovec_init(abspath, abspath_len));
        if (vhttp_cache_digests_lookup_by_url(src_stream->cache_digests, url.base, url.len) == vhttp_CACHE_DIGESTS_STATE_FRESH)
            return;
    }

    /* delayed initialization of casper (cookie-based), that MAY be used together to cache-digests */
    if (src_stream->req.hostconf->http2.casper.capacity_bits != 0) {
        if (!src_stream->pull.casper_is_ready) {
            src_stream->pull.casper_is_ready = 1;
            if (conn->casper == NULL)
                vhttp_http2_conn_init_casper(conn, src_stream->req.hostconf->http2.casper.capacity_bits);
            ssize_t header_index;
            for (header_index = -1;
                 (header_index = vhttp_find_header(&src_stream->req.headers, vhttp_TOKEN_COOKIE, header_index)) != -1;) {
                vhttp_header_t *header = src_stream->req.headers.entries + header_index;
                vhttp_http2_casper_consume_cookie(conn->casper, header->value.base, header->value.len);
            }
        }
    }

    /* update the push memo, and if it already pushed on the same connection, return */
    if (update_push_memo(conn, &src_stream->req, abspath, abspath_len))
        return;

    /* open the stream */
    vhttp_http2_stream_t *stream = vhttp_http2_stream_open(conn, conn->push_stream_ids.max_open + 2, NULL, &vhttp_http2_default_priority);
    stream->received_priority.dependency = src_stream->stream_id;
    stream->push.parent_stream_id = src_stream->stream_id;
    if (is_critical) {
        vhttp_http2_scheduler_open(&stream->_scheduler, &conn->scheduler, 257, 0);
    } else {
        vhttp_http2_scheduler_open(&stream->_scheduler, &src_stream->_scheduler.node, 16, 0);
    }
    vhttp_http2_stream_prepare_for_request(conn, stream);

    /* setup request */
    stream->req.input.method = (vhttp_iovec_t){vhttp_STRLIT("GET")};
    stream->req.input.scheme = src_stream->req.input.scheme;
    stream->req.input.authority =
        vhttp_strdup(&stream->req.pool, src_stream->req.input.authority.base, src_stream->req.input.authority.len);
    stream->req.input.path = vhttp_strdup(&stream->req.pool, abspath, abspath_len);
    stream->req.version = 0x200;

    { /* copy headers that may affect the response (of a cacheable response) */
        size_t i;
        for (i = 0; i != src_stream->req.headers.size; ++i) {
            vhttp_header_t *src_header = src_stream->req.headers.entries + i;
            /* currently only predefined headers are copiable */
            if (vhttp_iovec_is_token(src_header->name)) {
                vhttp_token_t *token = vhttp_STRUCT_FROM_MEMBER(vhttp_token_t, buf, src_header->name);
                if (token->flags.copy_for_push_request)
                    vhttp_add_header(&stream->req.pool, &stream->req.headers, token, NULL,
                                   vhttp_strdup(&stream->req.pool, src_header->value.base, src_header->value.len).base,
                                   src_header->value.len);
            }
        }
    }

    execute_or_enqueue_request(conn, stream);

    /* send push-promise ASAP (before the parent stream gets closed), even if execute_or_enqueue_request did not trigger the
     * invocation of send_headers */
    if (!stream->push.promise_sent && stream->state != vhttp_HTTP2_STREAM_STATE_END_STREAM)
        vhttp_http2_stream_send_push_promise(conn, stream);
}

static int foreach_request(vhttp_conn_t *_conn, int (*cb)(vhttp_req_t *req, void *cbdata), void *cbdata)
{
    vhttp_http2_conn_t *conn = (void *)_conn;
    vhttp_http2_stream_t *stream;
    kh_foreach_value(conn->streams, stream, {
        int ret = cb(&stream->req, cbdata);
        if (ret != 0)
            return ret;
    });
    return 0;
}

void vhttp_http2_accept(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock, struct timeval connected_at)
{
    vhttp_http2_conn_t *conn = create_conn(ctx->ctx, ctx->hosts, sock, connected_at);
    conn->http2_origin_frame = ctx->http2_origin_frame;
    sock->data = conn;
    vhttp_socket_read_start(conn->sock, on_read);
    update_idle_timeout(conn);
    if (sock->input->size != 0)
        on_read(sock, 0);
}

int vhttp_http2_handle_upgrade(vhttp_req_t *req, struct timeval connected_at)
{
    vhttp_http2_conn_t *http2conn = create_conn(req->conn->ctx, req->conn->hosts, NULL, connected_at);
    vhttp_http2_stream_t *stream;
    ssize_t connection_index, settings_index;
    vhttp_iovec_t settings_decoded;
    const char *err_desc;

    assert(req->version < 0x200); /* from HTTP/1.x */

    /* check that "HTTP2-Settings" is declared in the connection header */
    connection_index = vhttp_find_header(&req->headers, vhttp_TOKEN_CONNECTION, -1);
    assert(connection_index != -1);
    if (!vhttp_contains_token(req->headers.entries[connection_index].value.base, req->headers.entries[connection_index].value.len,
                            vhttp_STRLIT("http2-settings"), ',')) {
        goto Error;
    }

    /* decode the settings */
    if ((settings_index = vhttp_find_header(&req->headers, vhttp_TOKEN_HTTP2_SETTINGS, -1)) == -1) {
        goto Error;
    }
    if ((settings_decoded = vhttp_decode_base64url(&req->pool, req->headers.entries[settings_index].value.base,
                                                 req->headers.entries[settings_index].value.len))
            .base == NULL) {
        goto Error;
    }
    if (vhttp_http2_update_peer_settings(&http2conn->peer_settings, (uint8_t *)settings_decoded.base, settings_decoded.len,
                                       &err_desc) != 0) {
        goto Error;
    }

    /* open the stream, now that the function is guaranteed to succeed */
    stream = vhttp_http2_stream_open(http2conn, 1, req, &vhttp_http2_default_priority);
    vhttp_http2_scheduler_open(&stream->_scheduler, &http2conn->scheduler, vhttp_http2_default_priority.weight, 0);
    vhttp_http2_stream_prepare_for_request(http2conn, stream);

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_UPGRADE, NULL, vhttp_STRLIT("h2c"));
    vhttp_http1_upgrade(req, NULL, 0, on_upgrade_complete, http2conn);

    return 0;
Error:
    kh_destroy(vhttp_http2_stream_t, http2conn->streams);
    vhttp_destroy_connection(&http2conn->super);
    return -1;
}
