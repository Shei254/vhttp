/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd.
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
#include "../../../../lib/common/url.c"

static void test_normalize_path(void)
{
    vhttp_mem_pool_t pool;

    vhttp_mem_init_pool(&pool);

    size_t q;
    size_t *norm_indexes = NULL;
    vhttp_iovec_t input;
    vhttp_iovec_t b;

    input = vhttp_iovec_init(NULL, 0);
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 1);
    ok(memcmp(b.base, vhttp_STRLIT("/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("a"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 2);
    ok(memcmp(b.base, vhttp_STRLIT("/a")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 0);
    ok(norm_indexes[1] == 1);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("aa"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 3);
    ok(memcmp(b.base, vhttp_STRLIT("/aa")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 0);
    ok(norm_indexes[1] == 1);
    ok(norm_indexes[2] == 2);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 1);
    ok(memcmp(b.base, vhttp_STRLIT("/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("/."));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 1);
    ok(memcmp(b.base, vhttp_STRLIT("/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/./"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 1);
    ok(memcmp(b.base, vhttp_STRLIT("/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/.."));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 1);
    ok(memcmp(b.base, vhttp_STRLIT("/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/../"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 1);
    ok(memcmp(b.base, vhttp_STRLIT("/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/abc")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("/abc"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/abc")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/../def"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/def")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 9);
    ok(norm_indexes[2] == 10);
    ok(norm_indexes[3] == 11);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/../../def"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/def")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 12);
    ok(norm_indexes[2] == 13);
    ok(norm_indexes[3] == 14);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/./def"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 8);
    ok(memcmp(b.base, vhttp_STRLIT("/abc/def")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    ok(norm_indexes[4] == 5);
    ok(norm_indexes[5] == 8);
    ok(norm_indexes[6] == 9);
    ok(norm_indexes[7] == 10);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/././def"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 8);
    ok(memcmp(b.base, vhttp_STRLIT("/abc/def")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    ok(norm_indexes[4] == 5);
    ok(norm_indexes[5] == 10);
    ok(norm_indexes[6] == 11);
    ok(norm_indexes[7] == 12);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/def/ghi/../.."));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 5);
    ok(memcmp(b.base, vhttp_STRLIT("/abc/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    ok(norm_indexes[4] == 5);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/def/./."));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 9);
    ok(memcmp(b.base, vhttp_STRLIT("/abc/def/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    ok(norm_indexes[4] == 5);
    ok(norm_indexes[5] == 6);
    ok(norm_indexes[6] == 7);
    ok(norm_indexes[7] == 8);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/def/ghi/../."));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 9);
    ok(memcmp(b.base, vhttp_STRLIT("/abc/def/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    ok(norm_indexes[4] == 5);
    ok(norm_indexes[5] == 6);
    ok(norm_indexes[6] == 7);
    ok(norm_indexes[7] == 8);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/def/./.."));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 5);
    ok(memcmp(b.base, vhttp_STRLIT("/abc/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    ok(norm_indexes[4] == 5);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/def/.."));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 5);
    ok(memcmp(b.base, vhttp_STRLIT("/abc/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    ok(norm_indexes[4] == 5);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/def/."));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 9);
    ok(memcmp(b.base, vhttp_STRLIT("/abc/def/")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    ok(norm_indexes[4] == 5);
    ok(norm_indexes[5] == 6);
    ok(norm_indexes[6] == 7);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc?xx"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/abc")) == 0);
    ok(q == 4);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("/abc/../def?xx"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/def")) == 0);
    ok(q == 11);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 9);
    ok(norm_indexes[2] == 10);
    ok(norm_indexes[3] == 11);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/a%62c"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/abc")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 5);
    ok(norm_indexes[3] == 6);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/a%6"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/a%6")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/a%6?"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 4);
    ok(memcmp(b.base, vhttp_STRLIT("/a%6")) == 0);
    ok(q == 4);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 2);
    ok(norm_indexes[2] == 3);
    ok(norm_indexes[3] == 4);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/%25"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 2);
    ok(memcmp(b.base, vhttp_STRLIT("/%")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes != NULL);
    ok(norm_indexes[0] == 1);
    ok(norm_indexes[1] == 4);
    norm_indexes = NULL;

    input = vhttp_iovec_init(vhttp_STRLIT("/abc//"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 6);
    ok(memcmp(b.base, vhttp_STRLIT("/abc//")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("/abc//d"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 7);
    ok(memcmp(b.base, vhttp_STRLIT("/abc//d")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("//"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 2);
    ok(memcmp(b.base, vhttp_STRLIT("//")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("//abc"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 5);
    ok(memcmp(b.base, vhttp_STRLIT("//abc")) == 0);
    ok(q == SIZE_MAX);
    ok(norm_indexes == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("?abc"));
    b = vhttp_url_normalize_path(&pool, input.base, input.len, &q, &norm_indexes);
    ok(b.len == 1);
    ok(memcmp(b.base, vhttp_STRLIT("/")) == 0);

    vhttp_mem_clear_pool(&pool);
}

static void test_hostport(void)
{
    vhttp_iovec_t input, host;
    uint16_t port;
    const char *ret;

    input = vhttp_iovec_init(vhttp_STRLIT("127.0.0.1"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(ret == input.base + input.len);
    ok(vhttp_memis(host.base, host.len, vhttp_STRLIT("127.0.0.1")));
    ok(port == 65535);

    input = vhttp_iovec_init(vhttp_STRLIT("127.0.0.1/"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(strcmp(ret, "/") == 0);
    ok(vhttp_memis(host.base, host.len, vhttp_STRLIT("127.0.0.1")));
    ok(port == 65535);

    input = vhttp_iovec_init(vhttp_STRLIT("127.0.0.1?"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(strcmp(ret, "?") == 0);
    ok(vhttp_memis(host.base, host.len, vhttp_STRLIT("127.0.0.1")));
    ok(port == 65535);

    input = vhttp_iovec_init(vhttp_STRLIT("127.0.0.1:8081/"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(strcmp(ret, "/") == 0);
    ok(vhttp_memis(host.base, host.len, vhttp_STRLIT("127.0.0.1")));
    ok(port == 8081);

    input = vhttp_iovec_init(vhttp_STRLIT("127.0.0.1:8081?"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(strcmp(ret, "?") == 0);
    ok(vhttp_memis(host.base, host.len, vhttp_STRLIT("127.0.0.1")));
    ok(port == 8081);

    input = vhttp_iovec_init(vhttp_STRLIT("[::ffff:192.0.2.1]:8081/"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(strcmp(ret, "/") == 0);
    ok(vhttp_memis(host.base, host.len, vhttp_STRLIT("::ffff:192.0.2.1")));
    ok(port == 8081);

    input = vhttp_iovec_init(vhttp_STRLIT("[::ffff:192.0.2.1]:8081?"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(strcmp(ret, "?") == 0);
    ok(vhttp_memis(host.base, host.len, vhttp_STRLIT("::ffff:192.0.2.1")));
    ok(port == 8081);

    input = vhttp_iovec_init(vhttp_STRLIT("[::ffff:192.0.2.1:8081/"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(ret == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT(":8081/"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(ret == NULL);

    input = vhttp_iovec_init(vhttp_STRLIT("[]:8081/"));
    ret = vhttp_url_parse_hostport(input.base, input.len, &host, &port);
    ok(ret == NULL);
}

static void test_parse(void)
{
    vhttp_mem_pool_t pool;
    vhttp_url_t parsed;
    int ret;

    vhttp_mem_init_pool(&pool);

    ret = vhttp_url_parse(&pool, "http://example.com/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("example.com")));
    ok(parsed._port == 65535);
    ok(vhttp_url_get_port(&parsed) == 80);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/abc")));

    ret = vhttp_url_parse(&pool, "http://example.com", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("example.com")));
    ok(parsed._port == 65535);
    ok(vhttp_url_get_port(&parsed) == 80);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/")));

    ret = vhttp_url_parse(&pool, "http://example.com:81/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("example.com:81")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("example.com")));
    ok(parsed._port == 81);
    ok(vhttp_url_get_port(&parsed) == 81);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/abc")));

    ret = vhttp_url_parse(&pool, "http://example.com:81", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("example.com:81")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("example.com")));
    ok(parsed._port == 81);
    ok(vhttp_url_get_port(&parsed) == 81);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/")));

    ret = vhttp_url_parse(&pool, "https://example.com/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTPS);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("example.com")));
    ok(parsed._port == 65535);
    ok(vhttp_url_get_port(&parsed) == 443);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/abc")));

    ret = vhttp_url_parse(&pool, "http:/abc", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = vhttp_url_parse(&pool, "ftp://example.com/abc", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = vhttp_url_parse(&pool, "http://abc:111111/def", SIZE_MAX, &parsed);
    ok(ret != 0);

    ret = vhttp_url_parse(&pool, "http://[::ffff:192.0.2.128]", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("[::ffff:192.0.2.128]")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("::ffff:192.0.2.128")));
    ok(parsed._port == 65535);
    ok(vhttp_url_get_port(&parsed) == 80);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/")));

    ret = vhttp_url_parse(&pool, "https://[::ffff:192.0.2.128]/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTPS);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("[::ffff:192.0.2.128]")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("::ffff:192.0.2.128")));
    ok(parsed._port == 65535);
    ok(vhttp_url_get_port(&parsed) == 443);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/abc")));

    ret = vhttp_url_parse(&pool, "https://[::ffff:192.0.2.128]:111/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTPS);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("[::ffff:192.0.2.128]:111")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("::ffff:192.0.2.128")));
    ok(parsed._port == 111);
    ok(vhttp_url_get_port(&parsed) == 111);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/abc")));

    ret = vhttp_url_parse(&pool, "http://example.com:8080?abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/?abc")));

    vhttp_mem_clear_pool(&pool);
}

static void test_parse_relative(void)
{
    vhttp_mem_pool_t pool;
    vhttp_url_t parsed;
    int ret;

    vhttp_mem_init_pool(&pool);

    memset(&parsed, 0x55, sizeof(parsed));
    ret = vhttp_url_parse_relative(&pool, "abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == NULL);
    ok(parsed.authority.base == NULL);
    ok(parsed.host.base == NULL);
    ok(parsed._port == 65535);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("abc")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = vhttp_url_parse_relative(&pool, "/abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == NULL);
    ok(parsed.authority.base == NULL);
    ok(parsed.host.base == NULL);
    ok(parsed._port == 65535);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/abc")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = vhttp_url_parse_relative(&pool, "http:abc", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(parsed.authority.base == NULL);
    ok(parsed.host.base == NULL);
    ok(parsed._port == 65535);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("abc")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = vhttp_url_parse_relative(&pool, "//host", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == NULL);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("host")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("host")));
    ok(parsed._port == 65535);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = vhttp_url_parse_relative(&pool, "//host:12345/path", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == NULL);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("host:12345")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("host")));
    ok(parsed._port == 12345);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/path")));

    memset(&parsed, 0x55, sizeof(parsed));
    ret = vhttp_url_parse_relative(&pool, "https://host:12345/path", SIZE_MAX, &parsed);
    ok(ret == 0);
    ok(parsed.scheme == &vhttp_URL_SCHEME_HTTPS);
    ok(vhttp_memis(parsed.authority.base, parsed.authority.len, vhttp_STRLIT("host:12345")));
    ok(vhttp_memis(parsed.host.base, parsed.host.len, vhttp_STRLIT("host")));
    ok(parsed._port == 12345);
    ok(vhttp_memis(parsed.path.base, parsed.path.len, vhttp_STRLIT("/path")));

    vhttp_mem_clear_pool(&pool);
}

static void test_resolve(void)
{
    vhttp_mem_pool_t pool;
    vhttp_url_t base, relative, resolved;
    vhttp_iovec_t final;
    int ret;

    vhttp_mem_init_pool(&pool);

    ret = vhttp_url_parse(&pool, "http://example.com/dir/index.html", SIZE_MAX, &base);
    ok(ret == 0);

    ret = vhttp_url_parse_relative(&pool, "../assets/jquery.js", SIZE_MAX, &relative);
    ok(ret == 0);
    final = vhttp_url_resolve(&pool, &base, &relative, &resolved);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("http://example.com/assets/jquery.js")));
    ok(resolved.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(resolved.authority.base, resolved.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(resolved.host.base, resolved.host.len, vhttp_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(vhttp_url_get_port(&resolved) == 80);
    ok(vhttp_memis(resolved.path.base, resolved.path.len, vhttp_STRLIT("/assets/jquery.js")));

    ret = vhttp_url_parse_relative(&pool, "foo.html", SIZE_MAX, &relative);
    ok(ret == 0);
    final = vhttp_url_resolve(&pool, &base, &relative, &resolved);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("http://example.com/dir/foo.html")));
    ok(resolved.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(resolved.authority.base, resolved.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(resolved.host.base, resolved.host.len, vhttp_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(vhttp_url_get_port(&resolved) == 80);
    ok(vhttp_memis(resolved.path.base, resolved.path.len, vhttp_STRLIT("/dir/foo.html")));

    ret = vhttp_url_parse_relative(&pool, "./bar.txt", SIZE_MAX, &relative);
    ok(ret == 0);
    final = vhttp_url_resolve(&pool, &base, &relative, &resolved);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("http://example.com/dir/bar.txt")));
    ok(resolved.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(resolved.authority.base, resolved.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(resolved.host.base, resolved.host.len, vhttp_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(vhttp_url_get_port(&resolved) == 80);
    ok(vhttp_memis(resolved.path.base, resolved.path.len, vhttp_STRLIT("/dir/bar.txt")));

    ret = vhttp_url_parse_relative(&pool, "../../../traverse", SIZE_MAX, &relative);
    ok(ret == 0);
    final = vhttp_url_resolve(&pool, &base, &relative, &resolved);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("http://example.com/traverse")));
    ok(resolved.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(resolved.authority.base, resolved.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(resolved.host.base, resolved.host.len, vhttp_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(vhttp_url_get_port(&resolved) == 80);
    ok(vhttp_memis(resolved.path.base, resolved.path.len, vhttp_STRLIT("/traverse")));

    ret = vhttp_url_parse_relative(&pool, "http:foo.html", SIZE_MAX, &relative);
    ok(ret == 0);
    final = vhttp_url_resolve(&pool, &base, &relative, &resolved);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("http://example.com/dir/foo.html")));
    ok(resolved.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(resolved.authority.base, resolved.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(resolved.host.base, resolved.host.len, vhttp_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(vhttp_url_get_port(&resolved) == 80);
    ok(vhttp_memis(resolved.path.base, resolved.path.len, vhttp_STRLIT("/dir/foo.html")));

    ret = vhttp_url_parse_relative(&pool, "http:/icon.ico", SIZE_MAX, &relative);
    ok(ret == 0);
    final = vhttp_url_resolve(&pool, &base, &relative, &resolved);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("http://example.com/icon.ico")));
    ok(resolved.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(resolved.authority.base, resolved.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(resolved.host.base, resolved.host.len, vhttp_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(vhttp_url_get_port(&resolved) == 80);
    ok(vhttp_memis(resolved.path.base, resolved.path.len, vhttp_STRLIT("/icon.ico")));

    ret = vhttp_url_parse_relative(&pool, "https:/icon.ico", SIZE_MAX, &relative);
    ok(ret == 0);
    final = vhttp_url_resolve(&pool, &base, &relative, &resolved);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("https://example.com/icon.ico")));
    ok(resolved.scheme == &vhttp_URL_SCHEME_HTTPS);
    ok(vhttp_memis(resolved.authority.base, resolved.authority.len, vhttp_STRLIT("example.com")));
    ok(vhttp_memis(resolved.host.base, resolved.host.len, vhttp_STRLIT("example.com")));
    ok(resolved._port == 65535);
    ok(vhttp_url_get_port(&resolved) == 443);
    ok(vhttp_memis(resolved.path.base, resolved.path.len, vhttp_STRLIT("/icon.ico")));

    ret = vhttp_url_parse_relative(&pool, "//example.jp:81/icon.ico", SIZE_MAX, &relative);
    ok(ret == 0);
    final = vhttp_url_resolve(&pool, &base, &relative, &resolved);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("http://example.jp:81/icon.ico")));
    ok(resolved.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(vhttp_memis(resolved.authority.base, resolved.authority.len, vhttp_STRLIT("example.jp:81")));
    ok(vhttp_memis(resolved.host.base, resolved.host.len, vhttp_STRLIT("example.jp")));
    ok(resolved._port == 81);
    ok(vhttp_url_get_port(&resolved) == 81);
    ok(vhttp_memis(resolved.path.base, resolved.path.len, vhttp_STRLIT("/icon.ico")));

    final = vhttp_url_stringify(&pool, &base);
    ok(vhttp_memis(final.base, final.len, vhttp_STRLIT("http://example.com/dir/index.html")));

    vhttp_mem_clear_pool(&pool);
}

void test_lib__common__url_c(void)
{
    subtest("normalize_path", test_normalize_path);
    subtest("hostport", test_hostport);
    subtest("parse", test_parse);
    subtest("parse_relative", test_parse_relative);
    subtest("resolve", test_resolve);
}
