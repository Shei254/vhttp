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
#include <stddef.h>
#include <stdio.h>
#include "vhttp.h"

static ssize_t add_header(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, vhttp_iovec_t *name, const char *orig_name, const char *value,
                          size_t value_len, vhttp_header_flags_t flags)
{
    vhttp_header_t *slot;

    vhttp_vector_reserve(pool, headers, headers->size + 1);
    slot = headers->entries + headers->size++;

    slot->name = name;
    slot->value.base = (char *)value;
    slot->value.len = value_len;
    slot->orig_name = orig_name ? vhttp_strdup(pool, orig_name, name->len).base : NULL;
    slot->flags = flags;
    return headers->size - 1;
}

static inline vhttp_iovec_t *alloc_and_init_iovec(vhttp_mem_pool_t *pool, const char *base, size_t len)
{
    vhttp_iovec_t *iov = vhttp_mem_alloc_pool(pool, *iov, 1);
    iov->base = (char *)base;
    iov->len = len;
    return iov;
}

ssize_t vhttp_find_header(const vhttp_headers_t *headers, const vhttp_token_t *token, ssize_t cursor)
{
    for (++cursor; cursor < headers->size; ++cursor) {
        if (headers->entries[cursor].name == &token->buf) {
            return cursor;
        }
    }
    return -1;
}

ssize_t vhttp_find_header_by_str(const vhttp_headers_t *headers, const char *name, size_t name_len, ssize_t cursor)
{
    for (++cursor; cursor < headers->size; ++cursor) {
        vhttp_header_t *t = headers->entries + cursor;
        if (vhttp_memis(t->name->base, t->name->len, name, name_len)) {
            return cursor;
        }
    }
    return -1;
}

ssize_t vhttp_add_header(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, const vhttp_token_t *token, const char *orig_name,
                       const char *value, size_t value_len)
{
    return add_header(pool, headers, (vhttp_iovec_t *)&token->buf, orig_name, value, value_len, (vhttp_header_flags_t){0});
}

ssize_t vhttp_add_header_by_str(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, const char *lowercase_name, size_t lowercase_name_len,
                              int maybe_token, const char *orig_name, const char *value, size_t value_len)
{
    if (maybe_token) {
        const vhttp_token_t *token = vhttp_lookup_token(lowercase_name, lowercase_name_len);
        if (token != NULL) {
            return add_header(pool, headers, (vhttp_iovec_t *)token, orig_name, value, value_len, (vhttp_header_flags_t){0});
        }
    }
    return add_header(pool, headers, alloc_and_init_iovec(pool, lowercase_name, lowercase_name_len), orig_name, value, value_len,
                      (vhttp_header_flags_t){0});
}

ssize_t vhttp_set_header(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, const vhttp_token_t *token, const char *value, size_t value_len,
                       int overwrite_if_exists)
{
    ssize_t cursor = vhttp_find_header(headers, token, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            headers->entries[cursor].value = vhttp_iovec_init(value, value_len);
        }
        return cursor;
    } else {
        return vhttp_add_header(pool, headers, token, NULL, value, value_len);
    }
}

ssize_t vhttp_set_header_by_str(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, const char *lowercase_name, size_t lowercase_name_len,
                              int maybe_token, const char *value, size_t value_len, int overwrite_if_exists)
{
    ssize_t cursor;

    if (maybe_token) {
        const vhttp_token_t *token = vhttp_lookup_token(lowercase_name, lowercase_name_len);
        if (token != NULL) {
            return vhttp_set_header(pool, headers, token, value, value_len, overwrite_if_exists);
        }
    }

    cursor = vhttp_find_header_by_str(headers, lowercase_name, lowercase_name_len, -1);
    if (cursor != -1) {
        if (overwrite_if_exists) {
            headers->entries[cursor].value = vhttp_iovec_init(value, value_len);
        }
        return cursor;
    } else {
        return add_header(pool, headers, alloc_and_init_iovec(pool, lowercase_name, lowercase_name_len), NULL, value, value_len,
                          (vhttp_header_flags_t){0});
    }
}

ssize_t vhttp_set_header_token(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, const vhttp_token_t *token, const char *value,
                             size_t value_len)
{
    ssize_t found = -1;
    size_t i;
    for (i = 0; i != headers->size; ++i) {
        if (headers->entries[i].name == &token->buf) {
            if (vhttp_contains_token(headers->entries[i].value.base, headers->entries[i].value.len, value, value_len, ','))
                return -1;
            found = i;
        }
    }
    if (found != -1) {
        vhttp_header_t *dest = headers->entries + found;
        dest->value = vhttp_concat(pool, dest->value, vhttp_iovec_init(vhttp_STRLIT(", ")), vhttp_iovec_init(value, value_len));
        return found;
    } else {
        return vhttp_add_header(pool, headers, token, NULL, value, value_len);
    }
}

ssize_t vhttp_delete_header(vhttp_headers_t *headers, ssize_t cursor)
{
    assert(cursor != -1);

    --headers->size;
    memmove(headers->entries + cursor, headers->entries + cursor + 1, sizeof(vhttp_header_t) * (headers->size - cursor));

    return cursor;
}
