/*
 * Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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
#include "vhttp.h"
#include "vhttp/http2.h"
#include "vhttp/http2_internal.h"

static const char debug_state_string_open[] = "OPEN";
static const char debug_state_string_half_closed_remote[] = "HALF_CLOSED_REMOTE";
static const char debug_state_string_reserved_local[] = "RESERVED_LOCAL";

static const char *get_debug_state_string(vhttp_http2_stream_t *stream)
{
    if (vhttp_http2_stream_is_push(stream->stream_id)) {
        switch (stream->state) {
        case vhttp_HTTP2_STREAM_STATE_RECV_HEADERS:
        case vhttp_HTTP2_STREAM_STATE_RECV_BODY:
        case vhttp_HTTP2_STREAM_STATE_REQ_PENDING:
            return debug_state_string_reserved_local;
        case vhttp_HTTP2_STREAM_STATE_SEND_HEADERS:
        case vhttp_HTTP2_STREAM_STATE_SEND_BODY:
        case vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
            return debug_state_string_half_closed_remote;
        case vhttp_HTTP2_STREAM_STATE_IDLE:
        case vhttp_HTTP2_STREAM_STATE_END_STREAM:
            return NULL;
        }
    } else {
        switch (stream->state) {
        case vhttp_HTTP2_STREAM_STATE_RECV_HEADERS:
        case vhttp_HTTP2_STREAM_STATE_RECV_BODY:
            return debug_state_string_open;
        case vhttp_HTTP2_STREAM_STATE_REQ_PENDING:
        case vhttp_HTTP2_STREAM_STATE_SEND_HEADERS:
        case vhttp_HTTP2_STREAM_STATE_SEND_BODY:
        case vhttp_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
            return debug_state_string_half_closed_remote;
        case vhttp_HTTP2_STREAM_STATE_IDLE:
        case vhttp_HTTP2_STREAM_STATE_END_STREAM:
            return NULL;
        }
    }
    return NULL;
}

__attribute__((format(printf, 3, 4))) static void append_chunk(vhttp_mem_pool_t *pool, vhttp_iovec_vector_t *chunks, const char *fmt,
                                                               ...)
{
    va_list args;

    va_start(args, fmt);
    int size = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    assert(size > 0);

    vhttp_iovec_t v;
    v.base = vhttp_mem_alloc_pool(pool, char, size + 1);

    va_start(args, fmt);
    v.len = vsnprintf(v.base, size + 1, fmt, args);
    va_end(args);

    vhttp_vector_reserve(pool, chunks, chunks->size + 1);
    chunks->entries[chunks->size++] = v;
}

static void append_header_table_chunks(vhttp_mem_pool_t *pool, vhttp_iovec_vector_t *chunks, vhttp_hpack_header_table_t *header_table)
{
    int i;
    for (i = 0; i < header_table->num_entries; i++) {
        vhttp_hpack_header_table_entry_t *entry = vhttp_hpack_header_table_get(header_table, i);
        append_chunk(pool, chunks,
                     "\n"
                     "      [ \"%.*s\", \"%.*s\" ],",
                     (int)entry->name->len, entry->name->base, (int)entry->value->len, entry->value->base);
    }

    if (i > 0) {
        // remove the last commna
        --chunks->entries[chunks->size - 1].len;
    }
}

vhttp_http2_debug_state_t *vhttp_http2_get_debug_state(vhttp_req_t *req, int hpack_enabled)
{
    vhttp_http2_conn_t *conn = (vhttp_http2_conn_t *)req->conn;
    vhttp_http2_debug_state_t *state = vhttp_mem_alloc_pool(&req->pool, *state, 1);
    *state = (vhttp_http2_debug_state_t){{NULL}};

    state->conn_flow_in = vhttp_http2_window_get_avail(&conn->_input_window);
    state->conn_flow_out = vhttp_http2_window_get_avail(&conn->_write.window);

    append_chunk(&req->pool, &state->json,
                 "{\n"
                 "  \"version\": \"draft-01\",\n"
                 "  \"settings\": {\n"
                 "    \"SETTINGS_HEADER_TABLE_SIZE\": %" PRIu32 ",\n"
                 "    \"SETTINGS_ENABLE_PUSH\": %" PRIu32 ",\n"
                 "    \"SETTINGS_MAX_CONCURRENT_STREAMS\": %" PRIu32 ",\n"
                 "    \"SETTINGS_INITIAL_WINDOW_SIZE\": %" PRIu32 ",\n"
                 "    \"SETTINGS_MAX_FRAME_SIZE\": %" PRIu32 "\n"
                 "  },\n"
                 "  \"peerSettings\": {\n"
                 "    \"SETTINGS_HEADER_TABLE_SIZE\": %" PRIu32 ",\n"
                 "    \"SETTINGS_ENABLE_PUSH\": %" PRIu32 ",\n"
                 "    \"SETTINGS_MAX_CONCURRENT_STREAMS\": %" PRIu32 ",\n"
                 "    \"SETTINGS_INITIAL_WINDOW_SIZE\": %" PRIu32 ",\n"
                 "    \"SETTINGS_MAX_FRAME_SIZE\": %" PRIu32 "\n"
                 "  },\n"
                 "  \"connFlowIn\": %zd,\n"
                 "  \"connFlowOut\": %zd,\n"
                 "  \"streams\": {",
                 vhttp_HTTP2_SETTINGS_HOST_HEADER_TABLE_SIZE, vhttp_HTTP2_SETTINGS_HOST_ENABLE_PUSH,
                 conn->super.ctx->globalconf->http2.max_streams, vhttp_HTTP2_SETTINGS_HOST_STREAM_INITIAL_WINDOW_SIZE,
                 vhttp_HTTP2_SETTINGS_HOST_MAX_FRAME_SIZE, conn->peer_settings.header_table_size, conn->peer_settings.enable_push,
                 conn->peer_settings.max_concurrent_streams, conn->peer_settings.initial_window_size,
                 conn->peer_settings.max_frame_size, vhttp_http2_window_get_avail(&conn->_input_window),
                 vhttp_http2_window_get_avail(&conn->_write.window));

    /* encode streams */
    {
        vhttp_http2_stream_t *stream;
        kh_foreach_value(conn->streams, stream, {
            const char *state_string = get_debug_state_string(stream);
            if (state_string == NULL)
                continue;

            append_chunk(&req->pool, &state->json,
                         "\n"
                         "    \"%" PRIu32 "\": {\n"
                         "      \"state\": \"%s\",\n"
                         "      \"flowIn\": %zd,\n"
                         "      \"flowOut\": %zd,\n"
                         "      \"dataIn\": %zu,\n"
                         "      \"dataOut\": %" PRIu64 ",\n"
                         "      \"created\": %" PRIu64 "\n"
                         "    },",
                         stream->stream_id, state_string, vhttp_http2_window_get_avail(&stream->input_window.window),
                         vhttp_http2_window_get_avail(&stream->output_window), stream->req.req_body_bytes_received,
                         stream->req.bytes_sent, (uint64_t)stream->req.timestamps.request_begin_at.tv_sec);
        });

        if (conn->streams->size > 0) {
            // remove the last commna
            --state->json.entries[state->json.size - 1].len;
        }
    }

    append_chunk(&req->pool, &state->json,
                 "\n"
                 "  }");

    if (hpack_enabled) {
        /* encode inbound header table */
        append_chunk(&req->pool, &state->json,
                     ",\n"
                     "  \"hpack\": {\n"
                     "    \"inboundTableSize\": %zd,\n"
                     "    \"inboundDynamicHeaderTable\": [",
                     conn->_input_header_table.num_entries);
        append_header_table_chunks(&req->pool, &state->json, &conn->_input_header_table);

        /* encode outbound header table */
        append_chunk(&req->pool, &state->json,
                     "\n"
                     "    ],\n"
                     "    \"outboundTableSize\": %zd,\n"
                     "    \"outboundDynamicHeaderTable\": [",
                     conn->_output_header_table.num_entries);
        append_header_table_chunks(&req->pool, &state->json, &conn->_output_header_table);

        append_chunk(&req->pool, &state->json,
                     "\n"
                     "    ]\n"
                     "  }");
    }

    append_chunk(&req->pool, &state->json,
                 "\n"
                 "}\n");

    return state;
}
