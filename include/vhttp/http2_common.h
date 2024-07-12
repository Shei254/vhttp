/*
 * Copyright (c) 2018 Fastly Inc, Ichito Nagata
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
#ifndef vhttp__http2_common_h
#define vhttp__http2_common_h

#include "vhttp/string_.h"
#include "vhttp/header.h"
#include "vhttp/url.h"
#include "vhttp/memory.h"
#include "vhttp/cache_digests.h"

#define vhttp_HTTP2_SETTINGS_HEADER_TABLE_SIZE 1
#define vhttp_HTTP2_SETTINGS_ENABLE_PUSH 2
#define vhttp_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 3
#define vhttp_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE 4
#define vhttp_HTTP2_SETTINGS_MAX_FRAME_SIZE 5
#define vhttp_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 6
#define vhttp_HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL 8

/* defined as negated form of the error codes defined in HTTP2-spec section 7 */
#define vhttp_HTTP2_ERROR_NONE 0
#define vhttp_HTTP2_ERROR_PROTOCOL -1
#define vhttp_HTTP2_ERROR_INTERNAL -2
#define vhttp_HTTP2_ERROR_FLOW_CONTROL -3
#define vhttp_HTTP2_ERROR_SETTINGS_TIMEOUT -4
#define vhttp_HTTP2_ERROR_STREAM_CLOSED -5
#define vhttp_HTTP2_ERROR_FRAME_SIZE -6
#define vhttp_HTTP2_ERROR_REFUSED_STREAM -7
#define vhttp_HTTP2_ERROR_CANCEL -8
#define vhttp_HTTP2_ERROR_COMPRESSION -9
#define vhttp_HTTP2_ERROR_CONNECT -10
#define vhttp_HTTP2_ERROR_ENHANCE_YOUR_CALM -11
#define vhttp_HTTP2_ERROR_INADEQUATE_SECURITY -12
#define vhttp_HTTP2_ERROR_MAX 13
/* end of the HTTP2-spec defined errors */
#define vhttp_HTTP2_ERROR_INVALID_HEADER_CHAR                                                                                        \
    -254 /* an internal value indicating that invalid characters were found in the header name or value */
#define vhttp_HTTP2_ERROR_INCOMPLETE -255 /* an internal value indicating that all data is not ready */
#define vhttp_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY -256

typedef struct st_vhttp_http2_settings_t {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
} vhttp_http2_settings_t;

extern const vhttp_http2_settings_t vhttp_HTTP2_SETTINGS_DEFAULT;

int vhttp_http2_update_peer_settings(vhttp_http2_settings_t *settings, const uint8_t *src, size_t len, const char **err_desc);

typedef struct st_vhttp_http2_priority_t {
    int exclusive;
    uint32_t dependency;
    uint16_t weight;
} vhttp_http2_priority_t;

extern const vhttp_http2_priority_t vhttp_http2_default_priority;

#define vhttp_HTTP2_DEFAULT_OUTBUF_SIZE 81920 /* the target size of each write call; connection flow control window + alpha */
#define vhttp_HTTP2_DEFAULT_OUTBUF_SOFT_MAX_SIZE 524288 /* 512KB; stops reading if size exceeds this value */
#define vhttp_HTTP2_DEFAULT_OUTBUF_WRITE_TIMEOUT 60000  /* 60 seconds; close if write does not complete within the period */

/* hpack */

typedef struct st_vhttp_hpack_header_table_t {
    /* ring buffer */
    struct st_vhttp_hpack_header_table_entry_t *entries;
    size_t num_entries, entry_capacity, entry_start_index;
    /* size and capacities are 32+name_len+value_len (as defined by hpack spec.) */
    size_t hpack_size;
    size_t hpack_capacity;     /* the value set by SETTINGS_HEADER_TABLE_SIZE _and_ dynamic table size update */
    size_t hpack_max_capacity; /* the value set by SETTINGS_HEADER_TABLE_SIZE */
} vhttp_hpack_header_table_t;

typedef struct st_vhttp_hpack_header_table_entry_t {
    vhttp_iovec_t *name;
    vhttp_iovec_t *value;
    unsigned soft_errors;
} vhttp_hpack_header_table_entry_t;

void vhttp_hpack_dispose_header_table(vhttp_hpack_header_table_t *header_table);

size_t vhttp_hpack_encode_string(uint8_t *dst, const char *s, size_t len);
void vhttp_hpack_flatten_push_promise(vhttp_buffer_t **buf, vhttp_hpack_header_table_t *header_table, uint32_t hpack_capacity,
                                    uint32_t stream_id, size_t max_frame_size, const vhttp_url_scheme_t *scheme,
                                    vhttp_iovec_t authority, vhttp_iovec_t method, vhttp_iovec_t path, const vhttp_header_t *headers,
                                    size_t num_headers, uint32_t parent_stream_id);
size_t vhttp_hpack_flatten_response(vhttp_buffer_t **buf, vhttp_hpack_header_table_t *header_table, uint32_t hpack_capacity,
                                  uint32_t stream_id, size_t max_frame_size, int status, const vhttp_header_t *headers,
                                  size_t num_headers, const vhttp_iovec_t *server_name, size_t content_length, int is_end_stream);
void vhttp_hpack_flatten_request(vhttp_buffer_t **buf, vhttp_hpack_header_table_t *header_table, uint32_t hpack_capacity,
                               uint32_t stream_id, size_t max_frame_size, vhttp_iovec_t method, vhttp_url_t *url, vhttp_iovec_t protocol,
                               const vhttp_header_t *headers, size_t num_headers, int is_end_stream);
void vhttp_hpack_flatten_trailers(vhttp_buffer_t **buf, vhttp_hpack_header_table_t *header_table, uint32_t hpack_capacity,
                                uint32_t stream_id, size_t max_frame_size, const vhttp_header_t *headers, size_t num_headers);

extern vhttp_buffer_prototype_t vhttp_http2_wbuf_buffer_prototype;

/* frames */

#define vhttp_HTTP2_FRAME_HEADER_SIZE 9

#define vhttp_HTTP2_FRAME_TYPE_DATA 0
#define vhttp_HTTP2_FRAME_TYPE_HEADERS 1
#define vhttp_HTTP2_FRAME_TYPE_PRIORITY 2
#define vhttp_HTTP2_FRAME_TYPE_RST_STREAM 3
#define vhttp_HTTP2_FRAME_TYPE_SETTINGS 4
#define vhttp_HTTP2_FRAME_TYPE_PUSH_PROMISE 5
#define vhttp_HTTP2_FRAME_TYPE_PING 6
#define vhttp_HTTP2_FRAME_TYPE_GOAWAY 7
#define vhttp_HTTP2_FRAME_TYPE_WINDOW_UPDATE 8
#define vhttp_HTTP2_FRAME_TYPE_CONTINUATION 9
#define vhttp_HTTP2_FRAME_TYPE_ORIGIN 12

#define vhttp_HTTP2_FRAME_FLAG_END_STREAM 0x1
#define vhttp_HTTP2_FRAME_FLAG_ACK 0x1
#define vhttp_HTTP2_FRAME_FLAG_END_HEADERS 0x4
#define vhttp_HTTP2_FRAME_FLAG_PADDED 0x8
#define vhttp_HTTP2_FRAME_FLAG_PRIORITY 0x20

typedef struct st_vhttp_http2_frame_t {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    const uint8_t *payload;
} vhttp_http2_frame_t;

typedef struct st_vhttp_http2_data_payload_t {
    const uint8_t *data;
    size_t length;
} vhttp_http2_data_payload_t;

typedef struct st_vhttp_http2_headers_payload_t {
    vhttp_http2_priority_t priority;
    const uint8_t *headers;
    size_t headers_len;
} vhttp_http2_headers_payload_t;

typedef struct st_vhttp_http2_rst_stream_payload_t {
    uint32_t error_code;
} vhttp_http2_rst_stream_payload_t;

typedef struct st_vhttp_http2_ping_payload_t {
    uint8_t data[8];
} vhttp_http2_ping_payload_t;

typedef struct st_vhttp_http2_goaway_payload_t {
    uint32_t last_stream_id;
    uint32_t error_code;
    vhttp_iovec_t debug_data;
} vhttp_http2_goaway_payload_t;

typedef struct st_vhttp_http2_window_update_payload_t {
    uint32_t window_size_increment;
} vhttp_http2_window_update_payload_t;

typedef struct st_vhttp_http2_settings_kvpair {
    uint16_t key;
    uint32_t value;
} vhttp_http2_settings_kvpair_t;

uint8_t *vhttp_http2_encode_frame_header(uint8_t *dst, size_t length, uint8_t type, uint8_t flags, int32_t stream_id);

#define vhttp_http2_encode_rst_stream_frame(buf, stream_id, errnum)                                                                  \
    vhttp_http2__encode_rst_stream_frame(buf, stream_id, (vhttp_BUILD_ASSERT((errnum) > 0), errnum))

void vhttp_http2__encode_rst_stream_frame(vhttp_buffer_t **buf, uint32_t stream_id, int errnum);
void vhttp_http2_encode_ping_frame(vhttp_buffer_t **buf, int is_ack, const uint8_t *data);
void vhttp_http2_encode_goaway_frame(vhttp_buffer_t **buf, uint32_t last_stream_id, int errnum, vhttp_iovec_t additional_data);
void vhttp_http2_encode_settings_frame(vhttp_buffer_t **buf, vhttp_http2_settings_kvpair_t *settings, size_t num_settings);
void vhttp_http2_encode_window_update_frame(vhttp_buffer_t **buf, uint32_t stream_id, int32_t window_size_increment);
void vhttp_http2_encode_origin_frame(vhttp_buffer_t **buf, vhttp_iovec_t payload);
ssize_t vhttp_http2_decode_frame(vhttp_http2_frame_t *frame, const uint8_t *src, size_t len, size_t max_frame_size,
                               const char **err_desc);
int vhttp_http2_decode_data_payload(vhttp_http2_data_payload_t *payload, const vhttp_http2_frame_t *frame, const char **err_desc);
int vhttp_http2_decode_headers_payload(vhttp_http2_headers_payload_t *payload, const vhttp_http2_frame_t *frame, const char **err_desc);
int vhttp_http2_decode_priority_payload(vhttp_http2_priority_t *payload, const vhttp_http2_frame_t *frame, const char **err_desc);
int vhttp_http2_decode_rst_stream_payload(vhttp_http2_rst_stream_payload_t *payload, const vhttp_http2_frame_t *frame,
                                        const char **err_desc);
int vhttp_http2_decode_ping_payload(vhttp_http2_ping_payload_t *payload, const vhttp_http2_frame_t *frame, const char **err_desc);
int vhttp_http2_decode_goaway_payload(vhttp_http2_goaway_payload_t *payload, const vhttp_http2_frame_t *frame, const char **err_desc);
int vhttp_http2_decode_window_update_payload(vhttp_http2_window_update_payload_t *paylaod, const vhttp_http2_frame_t *frame,
                                           const char **err_desc, int *err_is_stream_level);

typedef struct st_vhttp_http2_window_t {
    ssize_t _avail;
} vhttp_http2_window_t;

static void vhttp_http2_window_init(vhttp_http2_window_t *window, uint32_t initial_window_size);
static int vhttp_http2_window_update(vhttp_http2_window_t *window, ssize_t delta);
static ssize_t vhttp_http2_window_get_avail(vhttp_http2_window_t *window);
static void vhttp_http2_window_consume_window(vhttp_http2_window_t *window, size_t bytes);

static vhttp_hpack_header_table_entry_t *vhttp_hpack_header_table_get(vhttp_hpack_header_table_t *table, size_t index);

/* misc */

static uint16_t vhttp_http2_decode16u(const uint8_t *src);
static uint32_t vhttp_http2_decode24u(const uint8_t *src);
static uint32_t vhttp_http2_decode32u(const uint8_t *src);
static uint8_t *vhttp_http2_encode16u(uint8_t *dst, uint16_t value);
static uint8_t *vhttp_http2_encode24u(uint8_t *dst, uint32_t value);
static uint8_t *vhttp_http2_encode32u(uint8_t *dst, uint32_t value);

/* inline definitions */

inline void vhttp_http2_window_init(vhttp_http2_window_t *window, uint32_t initial_window_size)
{
    window->_avail = initial_window_size;
}

inline int vhttp_http2_window_update(vhttp_http2_window_t *window, ssize_t delta)
{
    ssize_t v = window->_avail + delta;
    if (v > INT32_MAX)
        return -1;
    window->_avail = v;
    return 0;
}

inline ssize_t vhttp_http2_window_get_avail(vhttp_http2_window_t *window)
{
    return window->_avail;
}

inline void vhttp_http2_window_consume_window(vhttp_http2_window_t *window, size_t bytes)
{
    window->_avail -= bytes;
}

inline uint16_t vhttp_http2_decode16u(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

inline uint32_t vhttp_http2_decode24u(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

inline uint32_t vhttp_http2_decode32u(const uint8_t *src)
{
    return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
}

inline uint8_t *vhttp_http2_encode16u(uint8_t *dst, uint16_t value)
{
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline uint8_t *vhttp_http2_encode24u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline uint8_t *vhttp_http2_encode32u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 24;
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline vhttp_hpack_header_table_entry_t *vhttp_hpack_header_table_get(vhttp_hpack_header_table_t *table, size_t index)
{
    size_t entry_index = (index + table->entry_start_index) % table->entry_capacity;
    struct st_vhttp_hpack_header_table_entry_t *entry = table->entries + entry_index;
    assert(entry->name != NULL);
    return entry;
}

#endif
