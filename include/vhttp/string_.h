/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Justin Zhu
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
#ifndef vhttp__string_h
#define vhttp__string_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "vhttp/memory.h"

#define vhttp_STRLIT(s) (s), sizeof(s) - 1

#define vhttp_INT8_LONGEST_STR "-127"
#define vhttp_UINT8_LONGEST_STR "255"
#define vhttp_INT16_LONGEST_STR "-32768"
#define vhttp_UINT16_LONGEST_STR "65535"
#define vhttp_INT32_LONGEST_STR "-2147483648"
#define vhttp_UINT32_LONGEST_STR "4294967295"
#define vhttp_INT64_LONGEST_STR "-9223372036854775808"
#define vhttp_UINT64_LONGEST_STR "18446744073709551615"
#define vhttp_UINT64_LONGEST_HEX_STR "FFFFFFFFFFFFFFFF"

#define vhttp_SIZE_T_LONGEST_STR                                                                                                     \
    vhttp_UINT64_LONGEST_STR /* As it is hard to define a macro based on the actual size of size_t, we hard-code it to 64-bits and   \
                              assert that in string.c */

/**
 * duplicates given string
 * @param pool memory pool (or NULL to use malloc)
 * @param s source string
 * @param len length of the source string (the result of strlen(s) used in case len is SIZE_MAX)
 * @return buffer pointing to the duplicated string (buf is NUL-terminated but the length does not include the NUL char)
 */
vhttp_iovec_t vhttp_strdup(vhttp_mem_pool_t *pool, const char *s, size_t len);
/**
 * variant of vhttp_strdup that calls vhttp_mem_alloc_shared
 */
vhttp_iovec_t vhttp_strdup_shared(vhttp_mem_pool_t *pool, const char *s, size_t len);
/**
 * duplicates given string appending '/' to the tail if not found
 */
vhttp_iovec_t vhttp_strdup_slashed(vhttp_mem_pool_t *pool, const char *s, size_t len);
/**
 * tr/A-Z/a-z/
 */
static int vhttp_tolower(int ch);
/**
 * tr/A-Z/a-z/
 */
static void vhttp_strtolower(char *s, size_t len);
/**
 * copies and converts the string to lower-case
 */
static void vhttp_strcopytolower(char *d, const char *s, size_t len);
/**
 * tr/a-z/A-Z/
 */
static int vhttp_toupper(int ch);
/**
 * tr/a-z/A-Z/
 */
static void vhttp_strtoupper(char *s, size_t len);
/**
 * tests if target string (target_len bytes long) is equal to test string (test_len bytes long) after being converted to lower-case
 */
static int vhttp_lcstris(const char *target, size_t target_len, const char *test, size_t test_len);
/**
 * turns the length of a string into the length of the same string encoded in base64
 */
static size_t vhttp_base64_encode_capacity(size_t len);
/**
 * parses a positive number of return SIZE_MAX if failed
 */
size_t vhttp_strtosize(const char *s, size_t len);
/**
 * parses first positive number contained in *s or return SIZE_MAX if failed.
 * *s will set to right after the number in string or right after the end of string.
 */
size_t vhttp_strtosizefwd(char **s, size_t len);
/**
 * base64 url decoder
 */
vhttp_iovec_t vhttp_decode_base64url(vhttp_mem_pool_t *pool, const char *src, size_t len);
/**
 * base64 encoder (note: the function emits trailing '\0')
 */
size_t vhttp_base64_encode(char *dst, const void *src, size_t len, int url_encoded);
/**
 * decodes hexadecimal string
 */
int vhttp_hex_decode(void *dst, const char *src, size_t src_len);
/**
 * encodes binary into a hexadecimal string (with '\0' appended at last)
 */
void vhttp_hex_encode(char *dst, const void *src, size_t src_len);
/**
 * URI-escapes given string (as defined in RFC 3986)
 * @param pool memory pool or NULL to allocate memory using malloc
 * @return an encoded string which is NULL-terminated (NULL does not count as part of `.len`)
 */
vhttp_iovec_t vhttp_uri_escape(vhttp_mem_pool_t *pool, const char *s, size_t l, const char *preserve_chars);
/**
 * decodes a percent-encoded string (RFC 3986 Section 2.1)
 * @param pool memory pool or NULL to allocate memory using malloc
 * @param s source string
 * @param l length of source string
 * @return a decoded string which is NULL-terminated (NULL does not count as part of `.len`), or {NULL, 0} if failed
 */
vhttp_iovec_t vhttp_uri_unescape(vhttp_mem_pool_t *pool, const char *s, size_t l);
/**
 * returns the extension portion of path
 */
vhttp_iovec_t vhttp_get_filext(const char *path, size_t len);
/**
 * returns a vector with surrounding WS stripped
 */
vhttp_iovec_t vhttp_str_stripws(const char *s, size_t len);
/**
 * returns the offset of given substring or SIZE_MAX if not found
 */
size_t vhttp_strstr(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len);
/**
 * Parses a string into tokens or name-value pairs. Each token is returned as a tuple of (returned_pointer, *element_len). When the
 * input is fully consumed, NULL is returned. See t/00unit/lib/common/string.c for examples.
 *
 * @param iter   Iterator. When calling the function for the first time, this vector should point to the entire string to be parsed.
 * @param inner  Separator to separate tokens.
 * @param outer  The outer separator. When parsing a flat list, the values of `inner` and `outer` should be identical. When parsing
 *               a nested list, this value specifies the outer separator.  For example, (inner, outer) would be set to (';', ',')
 *               when parsing a Cache-Control header field value. In such case, boundary of sublists is signaled to the caller by
 *               returning a token pointing to the outer separator.
 * @param value  [optional] When a non-NULL address is given and if the found element contains `=`, that element is split into a
 *               name-value pair and the range of the value is returned using this parameter. The name is returned as the token.
 */
const char *vhttp_next_token(vhttp_iovec_t *iter, int inner, int outer, size_t *element_len, vhttp_iovec_t *value);
/**
 * tests if string needle exists within a separator-separated string (for handling "#rule" of RFC 2616)
 */
int vhttp_contains_token(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len, int separator);
/**
 * HTML-escapes a string
 * @param pool memory pool
 * @param src source string
 * @param len source length
 * @return the escaped string, or the source itself if escape was not necessary
 */
vhttp_iovec_t vhttp_htmlescape(vhttp_mem_pool_t *pool, const char *src, size_t len);
/**
 * concatenates a list of iovecs (with NUL termination)
 */
#define vhttp_concat(pool, ...)                                                                                                      \
    vhttp_concat_list(pool, (vhttp_iovec_t[]){__VA_ARGS__}, sizeof((vhttp_iovec_t[]){__VA_ARGS__}) / sizeof(vhttp_iovec_t))
vhttp_iovec_t vhttp_concat_list(vhttp_mem_pool_t *pool, vhttp_iovec_t *list, size_t count);
/**
 * joins the separated strings of iovecs into a single iovec
 */
vhttp_iovec_t vhttp_join_list(vhttp_mem_pool_t *pool, vhttp_iovec_t *list, size_t count, vhttp_iovec_t delimiter);
/**
 * splits the string str into a list of iovec
 */
void vhttp_split(vhttp_mem_pool_t *pool, vhttp_iovec_vector_t *list, vhttp_iovec_t str, const char needle);
/**
 * emits a two-line string to buf that graphically points to given location within the source string
 * @return 0 if successful
 */
int vhttp_str_at_position(char *buf, const char *src, size_t src_len, int lineno, int column);

int vhttp__lcstris_core(const char *target, const char *test, size_t test_len);

/**
 * Encode a Structured Field Value [RFC 8941] of type String ("sf-string" in the RFC)
 * @param pool memory pool (or NULL to use malloc)
 * @param s source string
 * @param slen length of source string; if slen==SIZE_MAX, then strlen(s) will be used
 * @return buffer pointing to the encoded string (buf is NUL-terminated but the length does not include the NUL char)
 */
vhttp_iovec_t vhttp_encode_sf_string(vhttp_mem_pool_t *pool, const char *s, size_t slen);

/* inline defs */

inline int vhttp_tolower(int ch)
{
    return 'A' <= ch && ch <= 'Z' ? ch + 0x20 : ch;
}

inline void vhttp_strtolower(char *s, size_t len)
{
    vhttp_strcopytolower(s, s, len);
}

inline void vhttp_strcopytolower(char *d, const char *s, size_t len)
{
    for (; len != 0; ++d, ++s, --len)
        *d = vhttp_tolower(*s);
}

inline int vhttp_toupper(int ch)
{
    return 'a' <= ch && ch <= 'z' ? ch - 0x20 : ch;
}

inline void vhttp_strtoupper(char *s, size_t len)
{
    for (; len != 0; ++s, --len)
        *s = vhttp_toupper(*s);
}

inline int vhttp_lcstris(const char *target, size_t target_len, const char *test, size_t test_len)
{
    if (target_len != test_len)
        return 0;
    return vhttp__lcstris_core(target, test, test_len);
}

inline size_t vhttp_base64_encode_capacity(size_t len)
{
    return (((len) + 2) / 3 * 4 + 1);
}

#ifdef __cplusplus
}
#endif

#endif
