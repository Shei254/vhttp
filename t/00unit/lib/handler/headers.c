/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include "../../test.h"
#include "../../../../lib/handler/headers.c"

static int headers_are(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, const char *s, size_t len)
{
    size_t i;
    vhttp_iovec_t flattened = {NULL};

    for (i = 0; i != headers->size; ++i) {
        flattened = vhttp_concat(pool, flattened, *headers->entries[i].name, vhttp_iovec_init(vhttp_STRLIT(": ")),
                               headers->entries[i].value, vhttp_iovec_init(vhttp_STRLIT("\n")));
    }

    return vhttp_memis(flattened.base, flattened.len, s, len);
}

static void setup_headers(vhttp_mem_pool_t *pool, vhttp_headers_t *headers)
{
    *headers = (vhttp_headers_t){NULL};
    vhttp_add_header(pool, headers, vhttp_TOKEN_CONTENT_TYPE, NULL, vhttp_STRLIT("text/plain"));
    vhttp_add_header(pool, headers, vhttp_TOKEN_CACHE_CONTROL, NULL, vhttp_STRLIT("public, max-age=86400"));
    vhttp_add_header(pool, headers, vhttp_TOKEN_SET_COOKIE, NULL, vhttp_STRLIT("a=b"));
    vhttp_add_header_by_str(pool, headers, vhttp_STRLIT("x-foo"), 0, NULL, vhttp_STRLIT("bar"));
}

void test_lib__handler__headers_c(void)
{
    vhttp_mem_pool_t pool;
    vhttp_headers_t headers;
    vhttp_headers_command_t cmd;
    vhttp_iovec_t header_str;

    vhttp_mem_init_pool(&pool);

    /* tests using token headers */
    setup_headers(&pool, &headers);
    ok(headers_are(&pool, &headers,
                   vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));
    vhttp_headers_command_arg_t args = (vhttp_headers_command_arg_t){&vhttp_TOKEN_SET_COOKIE->buf, {vhttp_STRLIT("c=d")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_ADD, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(
        &pool, &headers,
        vhttp_STRLIT(
            "content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\nset-cookie: c=d\n")));

    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&vhttp_TOKEN_CACHE_CONTROL->buf, {vhttp_STRLIT("public")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_APPEND, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(
        &pool, &headers,
        vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400, public\nset-cookie: a=b\nx-foo: bar\n")));

    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&vhttp_TOKEN_CACHE_CONTROL->buf, {vhttp_STRLIT("public")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_MERGE, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));

    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&vhttp_TOKEN_CACHE_CONTROL->buf, {vhttp_STRLIT("no-cache")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_SET, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   vhttp_STRLIT("content-type: text/plain\nset-cookie: a=b\nx-foo: bar\ncache-control: no-cache\n")));

    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&vhttp_TOKEN_CACHE_CONTROL->buf, {vhttp_STRLIT("no-cache")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_SETIFEMPTY, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));

    /* tests using non-token headers */
    header_str = vhttp_iovec_init(vhttp_STRLIT("x-foo"));
    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&header_str, {vhttp_STRLIT("baz")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_ADD, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(
        &pool, &headers,
        vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\nx-foo: baz\n")));

    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&header_str, {vhttp_STRLIT("bar")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_APPEND, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(
        &pool, &headers,
        vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar, bar\n")));

    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&header_str, {vhttp_STRLIT("bar")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_MERGE, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));

    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&header_str, {vhttp_STRLIT("baz")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_SET, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: baz\n")));

    setup_headers(&pool, &headers);
    args = (vhttp_headers_command_arg_t){&header_str, {vhttp_STRLIT("baz")}};
    cmd = (vhttp_headers_command_t){vhttp_HEADERS_CMD_SETIFEMPTY, &args, 1};
    vhttp_rewrite_headers(&pool, &headers, &cmd);
    ok(headers_are(&pool, &headers,
                   vhttp_STRLIT("content-type: text/plain\ncache-control: public, max-age=86400\nset-cookie: a=b\nx-foo: bar\n")));

    vhttp_mem_clear_pool(&pool);
}
