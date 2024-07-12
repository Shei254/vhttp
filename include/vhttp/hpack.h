/*
 * Copyright (c) 2014-2018 DeNA Co., Ltd., Kazuho Oku, Fastly
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
#ifndef vhttp__hpack_h
#define vhttp__hpack_h

#include <stddef.h>
#include <stdint.h>
#include "vhttp/header.h"
#include "vhttp/url.h"
#include "vhttp/cache_digests.h"

#define vhttp_HPACK_ENCODE_INT_MAX_LENGTH 10 /* first byte + 9 bytes (7*9==63 bits to hold positive numbers of int64_t) */

extern const char vhttp_hpack_err_missing_mandatory_pseudo_header[];
extern const char vhttp_hpack_err_invalid_pseudo_header[];
extern const char vhttp_hpack_err_found_upper_case_in_header_name[];
extern const char vhttp_hpack_err_unexpected_connection_specific_header[];
extern const char vhttp_hpack_err_invalid_content_length_header[];
extern const char vhttp_hpack_soft_err_found_invalid_char_in_header_name[];
extern const char vhttp_hpack_soft_err_found_invalid_char_in_header_value[];

#define vhttp_HPACK_SOFT_ERROR_BIT_INVALID_NAME 0x1
#define vhttp_HPACK_SOFT_ERROR_BIT_INVALID_VALUE 0x2

/**
 * encodes an integer (maximum size of the output excluding the first octet is vhttp_HTTP2_ENCODE_INT_MAX_LENGTH bytes)
 */
uint8_t *vhttp_hpack_encode_int(uint8_t *dst, int64_t value, unsigned prefix_bits);
/**
 * encodes a huffman string and returns its length, or returns SIZE_MAX if the resulting string would be longer than the input
 */
size_t vhttp_hpack_encode_huffman(uint8_t *dst, const uint8_t *src, size_t len);
/**
 * decodes an integer, or returns an error code (either vhttp_HTTP2_ERROR_COMPRESSION or vhttp_HTTP2_ERROR_INCOMPLETE)
 */
int64_t vhttp_hpack_decode_int(const uint8_t **src, const uint8_t *src_end, unsigned prefix_bits);
/**
 * Decodes a huffman string and returns its length, or SIZE_MAX if hard fails. The destination buffer must be at least double the
 * size of the input. For the soft errors being detected, the corresponding bits of `*soft_errors` will be set.
 */
size_t vhttp_hpack_decode_huffman(char *dst, unsigned *soft_errors, const uint8_t *src, size_t len, int is_name,
                                const char **err_desc);
/**
 * Validates header name and returns if hard validation succeeded. Upon failure, description of the hard failure will be stored in
 * `*err_desc`. Upon success, the corresponding bits in `*soft_errors` will be set for the soft errors being detected.
 */
int vhttp_hpack_validate_header_name(unsigned *soft_errors, const char *s, size_t len, const char **err_desc);
/**
 * Validates a header field value and returns soft errors.
 */
void vhttp_hpack_validate_header_value(unsigned *soft_errors, const char *s, size_t len);

#define vhttp_HPACK_PARSE_HEADERS_METHOD_EXISTS 1
#define vhttp_HPACK_PARSE_HEADERS_SCHEME_EXISTS 2
#define vhttp_HPACK_PARSE_HEADERS_PATH_EXISTS 4
#define vhttp_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS 8
#define vhttp_HPACK_PARSE_HEADERS_PROTOCOL_EXISTS 16

/**
 * Decodes a header field. This function must indicate soft errors using error codes, setting `*err_desc` to appropciate values.
 */
typedef int (*vhttp_hpack_decode_header_cb)(vhttp_mem_pool_t *pool, void *ctx, vhttp_iovec_t **name, vhttp_iovec_t *value,
                                          const uint8_t **const src, const uint8_t *src_end, const char **err_desc);
/**
 * HPACK implementation of `vhttp_hpack_decode_header_cb`.
 */
int vhttp_hpack_decode_header(vhttp_mem_pool_t *pool, void *_hpack_header_table, vhttp_iovec_t **name, vhttp_iovec_t *_value,
                            const uint8_t **const src, const uint8_t *src_end, const char **err_desc);
/**
 * Request parser that uses given callback as the decoder.
 */
int vhttp_hpack_parse_request(vhttp_mem_pool_t *pool, vhttp_hpack_decode_header_cb decode_cb, void *decode_ctx, vhttp_iovec_t *method,
                            const vhttp_url_scheme_t **scheme, vhttp_iovec_t *authority, vhttp_iovec_t *path, vhttp_iovec_t *protocol,
                            vhttp_headers_t *headers, int *pseudo_header_exists_map, size_t *content_length, vhttp_iovec_t *expect,
                            vhttp_cache_digests_t **digests, vhttp_iovec_t *datagram_flow_id, const uint8_t *src, size_t len,
                            const char **err_desc);
/**
 * Response parser that uses given callback as the decoder.
 */
int vhttp_hpack_parse_response(vhttp_mem_pool_t *pool, vhttp_hpack_decode_header_cb decode_cb, void *decode_ctx, int *status,
                             vhttp_headers_t *headers, vhttp_iovec_t *datagram_flow_id, const uint8_t *src, size_t len,
                             const char **err_desc);

#endif
