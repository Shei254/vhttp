/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Justin Zhu, Fastly, Inc.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "vhttp/string_.h"

vhttp_iovec_t vhttp_strdup(vhttp_mem_pool_t *pool, const char *s, size_t slen)
{
    /* We do not need this check to be here, but it needs to be somewhere, see the definition of vhttp_SIZE_T_LONGEST_STR */
    vhttp_BUILD_ASSERT(sizeof(size_t) <= sizeof(uint64_t));

    vhttp_iovec_t ret;

    if (slen == SIZE_MAX)
        slen = strlen(s);

    if (pool != NULL) {
        ret.base = vhttp_mem_alloc_pool(pool, char, slen + 1);
    } else {
        ret.base = vhttp_mem_alloc(slen + 1);
    }
    vhttp_memcpy(ret.base, s, slen);
    ret.base[slen] = '\0';
    ret.len = slen;
    return ret;
}

vhttp_iovec_t vhttp_strdup_shared(vhttp_mem_pool_t *pool, const char *s, size_t slen)
{
    vhttp_iovec_t ret;

    if (slen == SIZE_MAX)
        slen = strlen(s);

    ret.base = vhttp_mem_alloc_shared(pool, slen + 1, NULL);
    memcpy(ret.base, s, slen);
    ret.base[slen] = '\0';
    ret.len = slen;
    return ret;
}

vhttp_iovec_t vhttp_strdup_slashed(vhttp_mem_pool_t *pool, const char *src, size_t len)
{
    vhttp_iovec_t ret;

    ret.len = len != SIZE_MAX ? len : strlen(src);
    ret.base = pool != NULL ? vhttp_mem_alloc_pool(pool, char, ret.len + 2) : vhttp_mem_alloc(ret.len + 2);
    memcpy(ret.base, src, ret.len);
    if (ret.len != 0 && ret.base[ret.len - 1] != '/')
        ret.base[ret.len++] = '/';
    ret.base[ret.len] = '\0';

    return ret;
}

int vhttp__lcstris_core(const char *target, const char *test, size_t test_len)
{
    for (; test_len != 0; --test_len)
        if (vhttp_tolower(*target++) != *test++)
            return 0;
    return 1;
}

size_t vhttp_strtosize(const char *s, size_t len)
{
    uint64_t v = 0, m = 1;
    const char *p = s + len;

    if (len == 0)
        goto Error;

    while (1) {
        int ch = *--p;
        if (!('0' <= ch && ch <= '9'))
            goto Error;
        v += (ch - '0') * m;
        if (p == s)
            break;
        m *= 10;
        /* do not even try to overflow */
        if (m == 10000000000000000000ULL)
            goto Error;
    }

    if (v >= SIZE_MAX)
        goto Error;
    return v;

Error:
    return SIZE_MAX;
}

size_t vhttp_strtosizefwd(char **s, size_t len)
{
    uint64_t v, c;
    char *p = *s, *p_end = *s + len;

    if (len == 0)
        goto Error;

    int ch = *p++;
    if (!('0' <= ch && ch <= '9'))
        goto Error;
    v = ch - '0';
    c = 1;

    while (1) {
        ch = *p;
        if (!('0' <= ch && ch <= '9'))
            break;
        v *= 10;
        v += ch - '0';
        p++;
        c++;
        if (p == p_end)
            break;
        /* similar as above, do not even try to overflow */
        if (c == 20)
            goto Error;
    }

    if (v >= SIZE_MAX)
        goto Error;
    *s = p;
    return v;

Error:
    return SIZE_MAX;
}

static uint32_t decode_base64url_quad(const char *src)
{
    const char *src_end = src + 4;
    uint32_t decoded = 0;

    while (1) {
        if ('A' <= *src && *src <= 'Z') {
            decoded |= *src - 'A';
        } else if ('a' <= *src && *src <= 'z') {
            decoded |= *src - 'a' + 26;
        } else if ('0' <= *src && *src <= '9') {
            decoded |= *src - '0' + 52;
        } else if (*src == '-') {
            decoded |= 62;
        } else if (*src == '_') {
            decoded |= 63;
#if 1 /* curl uses normal base64 */
        } else if (*src == '+') {
            decoded |= 62;
        } else if (*src == '/') {
            decoded |= 63;
#endif
        } else {
            return UINT32_MAX;
        }
        if (++src == src_end)
            break;
        decoded <<= 6;
    }

    return decoded;
}

vhttp_iovec_t vhttp_decode_base64url(vhttp_mem_pool_t *pool, const char *src, size_t len)
{
    vhttp_iovec_t decoded;
    uint32_t t;
    uint8_t *dst;
    char remaining_input[4];

    decoded.len = len * 3 / 4;
    decoded.base = pool != NULL ? vhttp_mem_alloc_pool(pool, char, decoded.len + 1) : vhttp_mem_alloc(decoded.len + 1);
    dst = (uint8_t *)decoded.base;

    while (len >= 4) {
        if ((t = decode_base64url_quad(src)) == UINT32_MAX)
            goto Error;
        *dst++ = t >> 16;
        *dst++ = t >> 8;
        *dst++ = t;
        src += 4;
        len -= 4;
    }
    switch (len) {
    case 0:
        break;
    case 1:
        goto Error;
    case 2:
        remaining_input[0] = *src++;
        remaining_input[1] = *src++;
        remaining_input[2] = 'A';
        remaining_input[3] = 'A';
        if ((t = decode_base64url_quad(remaining_input)) == UINT32_MAX)
            goto Error;
        *dst++ = t >> 16;
        break;
    case 3:
        remaining_input[0] = *src++;
        remaining_input[1] = *src++;
        remaining_input[2] = *src++;
        remaining_input[3] = 'A';
        if ((t = decode_base64url_quad(remaining_input)) == UINT32_MAX)
            goto Error;
        *dst++ = t >> 16;
        *dst++ = t >> 8;
        break;
    }

    assert((char *)dst - decoded.base == decoded.len);
    decoded.base[decoded.len] = '\0';

    return decoded;

Error:
    if (pool == NULL)
        free(decoded.base);
    return vhttp_iovec_init(NULL, 0);
}

size_t vhttp_base64_encode(char *_dst, const void *_src, size_t len, int url_encoded)
{
    static const char *MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "abcdefghijklmnopqrstuvwxyz"
                             "0123456789+/";
    static const char *MAP_URL_ENCODED = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                         "abcdefghijklmnopqrstuvwxyz"
                                         "0123456789-_";

    char *dst = _dst;
    const uint8_t *src = _src;
    const char *map = url_encoded ? MAP_URL_ENCODED : MAP;
    uint32_t quad;

    for (; len >= 3; src += 3, len -= 3) {
        quad = ((uint32_t)src[0] << 16) | ((uint32_t)src[1] << 8) | src[2];
        *dst++ = map[quad >> 18];
        *dst++ = map[(quad >> 12) & 63];
        *dst++ = map[(quad >> 6) & 63];
        *dst++ = map[quad & 63];
    }
    if (len != 0) {
        quad = (uint32_t)src[0] << 16;
        *dst++ = map[quad >> 18];
        if (len == 2) {
            quad |= (uint32_t)src[1] << 8;
            *dst++ = map[(quad >> 12) & 63];
            *dst++ = map[(quad >> 6) & 63];
            if (!url_encoded)
                *dst++ = '=';
        } else {
            *dst++ = map[(quad >> 12) & 63];
            if (!url_encoded) {
                *dst++ = '=';
                *dst++ = '=';
            }
        }
    }

    *dst = '\0';
    return dst - _dst;
}

static int decode_hex(int ch)
{
    if ('0' <= ch && ch <= '9')
        return ch - '0';
    if ('A' <= ch && ch <= 'F')
        return ch - 'A' + 0xa;
    if ('a' <= ch && ch <= 'f')
        return ch - 'a' + 0xa;
    return -1;
}

int vhttp_hex_decode(void *_dst, const char *src, size_t src_len)
{
    unsigned char *dst = _dst;

    if (src_len % 2 != 0)
        return -1;
    for (; src_len != 0; src_len -= 2) {
        int hi, lo;
        if ((hi = decode_hex(*src++)) == -1 || (lo = decode_hex(*src++)) == -1)
            return -1;
        *dst++ = (hi << 4) | lo;
    }
    return 0;
}

void vhttp_hex_encode(char *dst, const void *_src, size_t src_len)
{
    const unsigned char *src = _src, *src_end = src + src_len;
    for (; src != src_end; ++src) {
        *dst++ = "0123456789abcdef"[*src >> 4];
        *dst++ = "0123456789abcdef"[*src & 0xf];
    }
    *dst = '\0';
}

vhttp_iovec_t vhttp_uri_escape(vhttp_mem_pool_t *pool, const char *s, size_t l, const char *preserve_chars)
{
    vhttp_iovec_t encoded;
    size_t i, capacity = l * 3 + 1;

    encoded.base = pool != NULL ? vhttp_mem_alloc_pool(pool, char, capacity) : vhttp_mem_alloc(capacity);
    encoded.len = 0;

    /* RFC 3986:
        path-noscheme = segment-nz-nc *( "/" segment )
        segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
        unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
        sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                     / "*" / "+" / "," / ";" / "="
    */
    for (i = 0; i != l; ++i) {
        int ch = s[i];
        if (('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z') || ('0' <= ch && ch <= '9') || ch == '-' || ch == '.' ||
            ch == '_' || ch == '~' || ch == '!' || ch == '$' || ch == '&' || ch == '\'' || ch == '(' || ch == ')' || ch == '*' ||
            ch == '+' || ch == ',' || ch == ';' || ch == '=' ||
            (ch != '\0' && preserve_chars != NULL && strchr(preserve_chars, ch) != NULL)) {
            encoded.base[encoded.len++] = ch;
        } else {
            encoded.base[encoded.len++] = '%';
            encoded.base[encoded.len++] = "0123456789ABCDEF"[(ch >> 4) & 0xf];
            encoded.base[encoded.len++] = "0123456789ABCDEF"[ch & 0xf];
        }
    }
    encoded.base[encoded.len] = '\0';

    return encoded;
}

vhttp_iovec_t vhttp_uri_unescape(vhttp_mem_pool_t *pool, const char *str, size_t len)
{
    vhttp_iovec_t decoded;

    decoded.base = pool != NULL ? vhttp_mem_alloc_pool(pool, char, len + 1) : vhttp_mem_alloc(len + 1);
    decoded.len = 0;

    for (size_t i = 0; i < len; ++i) {
        if (str[i] == '%') {
            if (i + 2 >= len)
                goto Fail;
            int hi = decode_hex(str[i + 1]);
            int lo = decode_hex(str[i + 2]);
            if (hi < 0 || lo < 0 || (hi == 0 && lo == 0))
                goto Fail;
            decoded.base[decoded.len++] = (hi << 4) | lo;
            i += 2;
        } else {
            decoded.base[decoded.len++] = str[i];
        }
    }
    decoded.base[decoded.len] = '\0';
    return decoded;

Fail:
    if (pool == NULL)
        free(decoded.base);
    return vhttp_iovec_init(NULL, 0);
}

vhttp_iovec_t vhttp_get_filext(const char *path, size_t len)
{
    const char *end = path + len, *p = end;

    while (--p != path) {
        if (*p == '.') {
            return vhttp_iovec_init(p + 1, end - (p + 1));
        } else if (*p == '/') {
            break;
        }
    }
    return vhttp_iovec_init(NULL, 0);
}

static int is_ws(int ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

vhttp_iovec_t vhttp_str_stripws(const char *s, size_t len)
{
    const char *end = s + len;

    while (s != end) {
        if (!is_ws(*s))
            break;
        ++s;
    }
    while (s != end) {
        if (!is_ws(end[-1]))
            break;
        --end;
    }
    return vhttp_iovec_init(s, end - s);
}

size_t vhttp_strstr(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len)
{
    /* TODO optimize */
    if (haysack_len >= needle_len) {
        size_t off, max = haysack_len - needle_len + 1;
        if (needle_len == 0)
            return 0;
        for (off = 0; off != max; ++off)
            if (haysack[off] == needle[0] && memcmp(haysack + off + 1, needle + 1, needle_len - 1) == 0)
                return off;
    }
    return SIZE_MAX;
}

/* note: returns a zero-width match as well */
const char *vhttp_next_token(vhttp_iovec_t *iter, int inner, int outer, size_t *element_len, vhttp_iovec_t *value)
{
    const char *cur = iter->base, *end = iter->base + iter->len, *token_start, *token_end;

    /* find start */
    for (;; ++cur) {
        if (cur == end)
            return NULL;
        if (!(*cur == ' ' || *cur == '\t'))
            break;
    }
    token_start = cur;
    token_end = cur;

    /* find last */
    for (;; ++cur) {
        if (cur == end)
            break;
        if (*cur == inner) {
            ++cur;
            break;
        }
        if (*cur == outer) {
            if (token_start == cur) {
                ++cur;
                token_end = cur;
            }
            break;
        }
        if (value != NULL && *cur == '=') {
            ++cur;
            goto FindValue;
        }
        if (!(*cur == ' ' || *cur == '\t'))
            token_end = cur + 1;
    }

    /* found */
    *iter = vhttp_iovec_init(cur, end - cur);
    *element_len = token_end - token_start;
    if (value != NULL)
        *value = (vhttp_iovec_t){NULL};
    return token_start;

FindValue:
    *iter = vhttp_iovec_init(cur, end - cur);
    *element_len = token_end - token_start;
    if ((value->base = (char *)vhttp_next_token(iter, inner, outer, &value->len, NULL)) == NULL) {
        *value = (vhttp_iovec_t){"", 0};
    } else if (vhttp_memis(value->base, value->len, vhttp_STRLIT(","))) {
        *value = (vhttp_iovec_t){"", 0};
        iter->base -= 1;
        iter->len += 1;
    }
    return token_start;
}

int vhttp_contains_token(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len, int separator)
{
    vhttp_iovec_t iter = vhttp_iovec_init(haysack, haysack_len);
    const char *token = NULL;
    size_t token_len = 0;

    while ((token = vhttp_next_token(&iter, separator, ',', &token_len, NULL)) != NULL) {
        if (vhttp_lcstris(token, token_len, needle, needle_len)) {
            return 1;
        }
    }
    return 0;
}

vhttp_iovec_t vhttp_htmlescape(vhttp_mem_pool_t *pool, const char *src, size_t len)
{
    const char *s, *end = src + len;
    size_t add_size = 0;

#define ENTITY_MAP()                                                                                                               \
    ENTITY('"', "&quot;");                                                                                                         \
    ENTITY('&', "&amp;");                                                                                                          \
    ENTITY('\'', "&#39;");                                                                                                         \
    ENTITY('<', "&lt;");                                                                                                           \
    ENTITY('>', "&gt;");

    for (s = src; s != end; ++s) {
        if ((unsigned)(unsigned char)*s - '"' <= '>' - '"') {
            switch (*s) {
#define ENTITY(code, quoted)                                                                                                       \
    case code:                                                                                                                     \
        add_size += sizeof(quoted) - 2;                                                                                            \
        break
                ENTITY_MAP()
#undef ENTITY
            }
        }
    }

    /* escape and return the result if necessary */
    if (add_size != 0) {
        /* allocate buffer and fill in the chars that are known not to require escaping */
        vhttp_iovec_t escaped = {vhttp_mem_alloc_pool(pool, char, len + add_size + 1), 0};
        /* fill-in the rest */
        for (s = src; s != end; ++s) {
            switch (*s) {
#define ENTITY(code, quoted)                                                                                                       \
    case code:                                                                                                                     \
        memcpy(escaped.base + escaped.len, quoted, sizeof(quoted) - 1);                                                            \
        escaped.len += sizeof(quoted) - 1;                                                                                         \
        break
                ENTITY_MAP()
#undef ENTITY
            default:
                escaped.base[escaped.len++] = *s;
                break;
            }
        }
        assert(escaped.len == len + add_size);
        escaped.base[escaped.len] = '\0';

        return escaped;
    }

#undef ENTITY_MAP

    /* no need not escape; return the original */
    return vhttp_iovec_init(src, len);
}

vhttp_iovec_t vhttp_concat_list(vhttp_mem_pool_t *pool, vhttp_iovec_t *list, size_t count)
{
    vhttp_iovec_t ret = {NULL, 0};
    size_t i;

    /* calc the length */
    for (i = 0; i != count; ++i) {
        ret.len += list[i].len;
    }

    /* allocate memory */
    if (pool != NULL)
        ret.base = vhttp_mem_alloc_pool(pool, char, ret.len + 1);
    else
        ret.base = vhttp_mem_alloc(ret.len + 1);

    /* concatenate */
    ret.len = 0;
    for (i = 0; i != count; ++i) {
        vhttp_memcpy(ret.base + ret.len, list[i].base, list[i].len);
        ret.len += list[i].len;
    }
    ret.base[ret.len] = '\0';

    return ret;
}

vhttp_iovec_t vhttp_join_list(vhttp_mem_pool_t *pool, vhttp_iovec_t *list, size_t count, vhttp_iovec_t delimiter)
{
    if (count == 0) {
        return vhttp_iovec_init(NULL, 0);
    }

    size_t joined_len = 0;
    vhttp_iovec_t *joined = alloca(sizeof(*joined) * (count * 2 - 1));

    size_t i;
    for (i = 0; i != count; ++i) {
        if (i != 0) {
            joined[joined_len++] = delimiter;
        }
        joined[joined_len++] = list[i];
    }
    return vhttp_concat_list(pool, joined, joined_len);
}

void vhttp_split(vhttp_mem_pool_t *pool, vhttp_iovec_vector_t *list, vhttp_iovec_t str, const char needle)
{
    const char *p = str.base, *end = str.base + str.len, *found;

    while (p < end && (found = memchr(p, needle, end - p)) != NULL) {
        vhttp_vector_reserve(pool, list, list->size + 1);
        list->entries[list->size++] = vhttp_strdup(pool, p, found - p);
        p = found + 1;
    }
    vhttp_vector_reserve(pool, list, list->size + 1);
    list->entries[list->size++] = vhttp_strdup(pool, p, end - p);
}

int vhttp_str_at_position(char *buf, const char *src, size_t src_len, int lineno, int column)
{
    const char *src_end = src + src_len;
    int i;

    /* find the line */
    if (lineno <= 0 || column <= 0)
        return -1;
    for (--lineno; lineno != 0; --lineno) {
        do {
            if (src == src_end)
                return -1;
        } while (*src++ != '\n');
    }

    /* adjust the starting column */
    while (column > 40) {
        if (src != src_end)
            ++src;
        --column;
    }

    /* emit */
    for (i = 1; i <= 76; ++i) {
        if (src == src_end || *src == '\n')
            break;
        *buf++ = *src++;
    }
    if (i < column)
        column = i;
    *buf++ = '\n';
    for (i = 1; i < column; ++i)
        *buf++ = ' ';
    *buf++ = '^';
    *buf++ = '\n';
    *buf = '\0';
    return 0;
}

vhttp_iovec_t vhttp_encode_sf_string(vhttp_mem_pool_t *pool, const char *s, size_t slen)
{
    if (slen == SIZE_MAX)
        slen = strlen(s);

    /* https://tools.ietf.org/html/rfc8941#section-3.3.3 */
    size_t to_escape = 0;
    for (size_t i = 0; i < slen; ++i) {
        if (s[i] == '\\' || s[i] == '"')
            ++to_escape;
    }

    vhttp_iovec_t ret;
    ret.len = slen + to_escape + 2;
    if (pool != NULL) {
        ret.base = vhttp_mem_alloc_pool(pool, char, ret.len + 1);
    } else {
        ret.base = vhttp_mem_alloc(ret.len + 1);
    }
    char *dst = ret.base;
    *dst++ = '"';
    for (size_t i = 0; i < slen; ++i) {
        if (s[i] == '\\' || s[i] == '"')
            *dst++ = '\\';
        *dst++ = s[i];
    }
    *dst++ = '"';
    *dst++ = '\0';
    return ret;
}
