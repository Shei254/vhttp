/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#ifndef vhttp__qpack_h
#define vhttp__qpack_h

#include "vhttp/hpack.h"

typedef struct st_vhttp_qpack_decoder_t vhttp_qpack_decoder_t;
typedef struct st_vhttp_qpack_encoder_t vhttp_qpack_encoder_t;

extern const char *vhttp_qpack_err_header_name_too_long;
extern const char *vhttp_qpack_err_header_value_too_long;
extern const char *vhttp_qpack_err_header_exceeds_table_size;
extern const char *vhttp_qpack_err_invalid_max_size;
extern const char *vhttp_qpack_err_invalid_static_reference;
extern const char *vhttp_qpack_err_invalid_dynamic_reference;
extern const char *vhttp_qpack_err_invalid_duplicate;
extern const char *vhttp_qpack_err_invalid_pseudo_header;

vhttp_qpack_decoder_t *vhttp_qpack_create_decoder(uint32_t header_table_size, uint16_t max_blocked);
void vhttp_qpack_destroy_decoder(vhttp_qpack_decoder_t *qpack);
/**
 * This function processes a stream of QPACK encoder instructions provided in [*src, src_end), and updates `*src` to point to the
 * beginning of the first partial instruction being found.
 * This decoder does not enforce its own limits to the instruction size. Instead, it relies on the caller's flow control to block
 * encoder instructions that exceed the flow control size. That is how we protect us from memory exhaustion attacks.
 */
int vhttp_qpack_decoder_handle_input(vhttp_qpack_decoder_t *qpack, int64_t **unblocked_stream_ids, size_t *num_unblocked,
                                   const uint8_t **src, const uint8_t *src_end, const char **err_desc);
size_t vhttp_qpack_decoder_send_state_sync(vhttp_qpack_decoder_t *qpack, uint8_t *outbuf);
size_t vhttp_qpack_decoder_send_stream_cancel(vhttp_qpack_decoder_t *qpack, uint8_t *outbuf, int64_t stream_id);

/**
 * Parses a QPACK request. The input should be the *payload* of the HTTP/3 HEADERS frame.
 */
int vhttp_qpack_parse_request(vhttp_mem_pool_t *pool, vhttp_qpack_decoder_t *qpack, int64_t stream_id, vhttp_iovec_t *method,
                            const vhttp_url_scheme_t **scheme, vhttp_iovec_t *authority, vhttp_iovec_t *path, vhttp_iovec_t *protocol,
                            vhttp_headers_t *headers, int *pseudo_header_exists_map, size_t *content_length, vhttp_iovec_t *expect,
                            vhttp_cache_digests_t **digests, vhttp_iovec_t *datagram_flow_id, uint8_t *outbuf, size_t *outbufsize,
                            const uint8_t *src, size_t len, const char **err_desc);
/**
 * Parses a QPACK response. The input should be the *payload* of the HTTP/3 HEADERS frame. `outbuf` should be at least
 * vhttp_HPACK_ENCODE_INT_MAX_LENGTH long.
 */
int vhttp_qpack_parse_response(vhttp_mem_pool_t *pool, vhttp_qpack_decoder_t *qpack, int64_t stream_id, int *status,
                             vhttp_headers_t *headers, vhttp_iovec_t *datagram_flow_id, uint8_t *outbuf, size_t *outbufsize,
                             const uint8_t *src, size_t len, const char **err_desc);

vhttp_qpack_encoder_t *vhttp_qpack_create_encoder(uint32_t header_table_size, uint16_t max_blocked);
void vhttp_qpack_destroy_encoder(vhttp_qpack_encoder_t *qpack);
/**
 * Handles packets sent to the QPACK encoder (i.e., the bytes carried by the "decoder" stream)
 * @param qpack can be NULL
 */
int vhttp_qpack_encoder_handle_input(vhttp_qpack_encoder_t *qpack, const uint8_t **src, const uint8_t *src_end, const char **err_desc);
/**
 * Flattens a QPACK request. The output includes the HTTP/3 frame header.
 * @param encoder_buf optional parameter pointing to buffer to store encoder stream data. Set to NULL to avoid blocking.
 */
vhttp_iovec_t vhttp_qpack_flatten_request(vhttp_qpack_encoder_t *qpack, vhttp_mem_pool_t *pool, int64_t stream_id,
                                      vhttp_byte_vector_t *encoder_buf, vhttp_iovec_t method, const vhttp_url_scheme_t *scheme,
                                      vhttp_iovec_t authority, vhttp_iovec_t path, vhttp_iovec_t protocol, const vhttp_header_t *headers,
                                      size_t num_headers, vhttp_iovec_t datagram_flow_id);
/**
 * Flattens a QPACK response. The output includes the HTTP/3 frame header.
 */
vhttp_iovec_t vhttp_qpack_flatten_response(vhttp_qpack_encoder_t *qpack, vhttp_mem_pool_t *pool, int64_t stream_id,
                                       vhttp_byte_vector_t *encoder_buf, int status, const vhttp_header_t *headers, size_t num_headers,
                                       const vhttp_iovec_t *server_name, size_t content_length, vhttp_iovec_t datagram_flow_id,
                                       size_t *serialized_header_len);

#endif
