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
#include <stdarg.h>
#include "../../test.h"
#include "../../../../lib/http2/hpack.c"

static void test_request(vhttp_iovec_t first_req, vhttp_iovec_t second_req, vhttp_iovec_t third_req)
{
    vhttp_hpack_header_table_t header_table;
    vhttp_req_t req;
    vhttp_iovec_t in;
    int r, pseudo_headers_map;
    vhttp_iovec_t expect;
    size_t content_length;
    const char *err_desc = NULL;

    memset(&header_table, 0, sizeof(header_table));
    header_table.hpack_capacity = 4096;

    memset(&req, 0, sizeof(req));
    vhttp_mem_init_pool(&req.pool);
    in = first_req;
    r = vhttp_hpack_parse_request(&req.pool, vhttp_hpack_decode_header, &header_table, &req.input.method, &req.input.scheme,
                                &req.input.authority, &req.input.path, &req.upgrade, &req.headers, &pseudo_headers_map,
                                &content_length, &expect, NULL, NULL, (const uint8_t *)in.base, in.len, &err_desc);
    ok(r == 0);
    ok(req.input.authority.len == 15);
    ok(memcmp(req.input.authority.base, vhttp_STRLIT("www.example.com")) == 0);
    ok(req.input.method.len == 3);
    ok(memcmp(req.input.method.base, vhttp_STRLIT("GET")) == 0);
    ok(req.input.path.len == 1);
    ok(memcmp(req.input.path.base, vhttp_STRLIT("/")) == 0);
    ok(req.input.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(req.headers.size == 0);

    vhttp_mem_clear_pool(&req.pool);

    memset(&req, 0, sizeof(req));
    vhttp_mem_init_pool(&req.pool);
    in = second_req;
    r = vhttp_hpack_parse_request(&req.pool, vhttp_hpack_decode_header, &header_table, &req.input.method, &req.input.scheme,
                                &req.input.authority, &req.input.path, &req.upgrade, &req.headers, &pseudo_headers_map,
                                &content_length, &expect, NULL, NULL, (const uint8_t *)in.base, in.len, &err_desc);
    ok(r == 0);
    ok(req.input.authority.len == 15);
    ok(memcmp(req.input.authority.base, vhttp_STRLIT("www.example.com")) == 0);
    ok(req.input.method.len == 3);
    ok(memcmp(req.input.method.base, vhttp_STRLIT("GET")) == 0);
    ok(req.input.path.len == 1);
    ok(memcmp(req.input.path.base, vhttp_STRLIT("/")) == 0);
    ok(req.input.scheme == &vhttp_URL_SCHEME_HTTP);
    ok(req.headers.size == 1);
    ok(vhttp_memis(req.headers.entries[0].name->base, req.headers.entries[0].name->len, vhttp_STRLIT("cache-control")));
    ok(vhttp_lcstris(req.headers.entries[0].value.base, req.headers.entries[0].value.len, vhttp_STRLIT("no-cache")));

    vhttp_mem_clear_pool(&req.pool);

    memset(&req, 0, sizeof(req));
    vhttp_mem_init_pool(&req.pool);
    in = third_req;
    r = vhttp_hpack_parse_request(&req.pool, vhttp_hpack_decode_header, &header_table, &req.input.method, &req.input.scheme,
                                &req.input.authority, &req.input.path, &req.upgrade, &req.headers, &pseudo_headers_map,
                                &content_length, &expect, NULL, NULL, (const uint8_t *)in.base, in.len, &err_desc);
    ok(r == 0);
    ok(req.input.authority.len == 15);
    ok(memcmp(req.input.authority.base, vhttp_STRLIT("www.example.com")) == 0);
    ok(req.input.method.len == 3);
    ok(memcmp(req.input.method.base, vhttp_STRLIT("GET")) == 0);
    ok(req.input.path.len == 11);
    ok(memcmp(req.input.path.base, vhttp_STRLIT("/index.html")) == 0);
    ok(req.input.scheme == &vhttp_URL_SCHEME_HTTPS);
    ok(req.headers.size == 1);
    ok(vhttp_memis(req.headers.entries[0].name->base, req.headers.entries[0].name->len, vhttp_STRLIT("custom-key")));
    ok(vhttp_lcstris(req.headers.entries[0].value.base, req.headers.entries[0].value.len, vhttp_STRLIT("custom-value")));

    vhttp_hpack_dispose_header_table(&header_table);
    vhttp_mem_clear_pool(&req.pool);
}

static void check_flatten(vhttp_hpack_header_table_t *header_table, vhttp_res_t *res, const char *expected, size_t expected_len)
{
    vhttp_buffer_t *buf;
    vhttp_http2_frame_t frame;
    const char *err_desc;

    vhttp_buffer_init(&buf, &vhttp_socket_buffer_prototype);
    vhttp_hpack_flatten_response(&buf, header_table, vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size, 1,
                               vhttp_HTTP2_SETTINGS_DEFAULT.max_frame_size, res->status, res->headers.entries, res->headers.size,
                               NULL, SIZE_MAX, 0);

    ok(vhttp_http2_decode_frame(&frame, (uint8_t *)buf->bytes, buf->size, vhttp_HTTP2_SETTINGS_DEFAULT.max_frame_size, &err_desc) > 0);
    ok(vhttp_memis(frame.payload, frame.length, expected, expected_len));

    vhttp_buffer_dispose(&buf);
}

static void test_hpack(void)
{
    vhttp_mem_pool_t pool;
    const char *err_desc;

    vhttp_mem_init_pool(&pool);

    note("decode_int");
    {
        vhttp_iovec_t in;
        const uint8_t *p;
        int64_t out;
#define TEST(input, output)                                                                                                        \
    in = vhttp_iovec_init(vhttp_STRLIT(input));                                                                                        \
    p = (const uint8_t *)in.base;                                                                                                  \
    out = vhttp_hpack_decode_int(&p, p + in.len, 7);                                                                                 \
    ok(out == output);                                                                                                             \
    ok(output == vhttp_HTTP2_ERROR_COMPRESSION || p == (const uint8_t *)in.base + in.len);
        TEST("\x00", 0);
        TEST("\x03", 3);
        TEST("\x81", 1);
        TEST("\x7f\x00", 127);
        TEST("\x7f\x01", 128);
        TEST("\x7f\x7f", 254);
        TEST("\x7f\x81\x00", 128);
        TEST("\x7f\x80\x01", 255);
        TEST("\x7f\xff\xff\xff\x7f", 0xfffffff + 127);
        TEST("\x7f\x80\xff\xff\xff\xff\xff\xff\xff\x7f", INT64_MAX);
        /* failures */
        TEST("", vhttp_HTTP2_ERROR_INCOMPLETE);
        TEST("\x7f", vhttp_HTTP2_ERROR_INCOMPLETE);
        TEST("\x7f\xff", vhttp_HTTP2_ERROR_INCOMPLETE);
        TEST("\x7f\xff\xff\xff\xff", vhttp_HTTP2_ERROR_INCOMPLETE);
        TEST("\x7f\x81\xff\xff\xff\xff\xff\xff\xff\x7f", vhttp_HTTP2_ERROR_COMPRESSION);
        TEST("\x7f\x80\xff\xff\xff\xff\xff\xff\xff\xff", vhttp_HTTP2_ERROR_COMPRESSION);
#undef TEST
    }

    note("encode_int");
    {
        uint8_t buf[16];
        size_t len;
#define TEST(encoded, value)                                                                                                       \
    memset(buf, 0, sizeof(buf));                                                                                                   \
    len = vhttp_hpack_encode_int(buf, value, 7) - buf;                                                                               \
    ok(len == sizeof(encoded) - 1);                                                                                                \
    ok(memcmp(buf, encoded, sizeof(encoded) - 1) == 0);
        TEST("\x00", 0);
        TEST("\x03", 3);
        TEST("\x7e", 126);
        TEST("\x7f\x00", 127);
        TEST("\x7f\x01", 128);
        TEST("\x7f\x7f", 254);
        TEST("\x7f\x80\x01", 255);
        TEST("\x7f\xff\xff\xff\x7f", 0xfffffff + 127);
        TEST("\x7f\x80\xff\xff\xff\xff\xff\xff\xff\x7f", INT64_MAX);
#undef TEST
    }

    note("decode_huffman");
    {
        vhttp_iovec_t huffcode = {vhttp_STRLIT("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")};
        char buf[32];
        unsigned soft_errors = 0;
        const char *err_desc = NULL;
        size_t len = vhttp_hpack_decode_huffman(buf, &soft_errors, (const uint8_t *)huffcode.base, huffcode.len, 0, &err_desc);
        ok(len == sizeof("www.example.com") - 1);
        ok(memcmp(buf, "www.example.com", len) == 0);
        ok(soft_errors == 0);
        ok(err_desc == NULL);
    }
    vhttp_mem_clear_pool(&pool);

    note("decode_string_bogus");
    {
        char *str = "\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
        const uint8_t *buf;
        unsigned soft_errors = 0;
        const char *errstr = NULL;
        size_t len;
        len = strlen(str);
        buf = (const uint8_t *)str;
        /* since we're only passing one byte, decode_string should fail */
        vhttp_iovec_t *decoded = decode_string(&pool, &soft_errors, &buf, &buf[1], 0, &errstr);
        ok(decoded == NULL);
    }
    vhttp_mem_clear_pool(&pool);

    note("decode_header (literal header field with indexing)");
    {
        vhttp_hpack_header_table_t header_table;
        vhttp_iovec_t in, *name, value;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = vhttp_iovec_init(
            vhttp_STRLIT("\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x68\x65\x61\x64\x65\x72"));
        const uint8_t *p = (const uint8_t *)in.base;
        err_desc = NULL;
        r = vhttp_hpack_decode_header(&pool, &header_table, &name, &value, &p, p + in.len, &err_desc);
        ok(r == 0);
        ok(name->len == 10);
        ok(strcmp(name->base, "custom-key") == 0);
        ok(value.len == 13);
        ok(strcmp(value.base, "custom-header") == 0);
        ok(header_table.hpack_size == 55);
    }
    vhttp_mem_clear_pool(&pool);

    note("decode_header (literal header field without indexing)");
    {
        vhttp_hpack_header_table_t header_table;
        vhttp_iovec_t in, *name, value;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = vhttp_iovec_init(vhttp_STRLIT("\x04\x0c\x2f\x73\x61\x6d\x70\x6c\x65\x2f\x70\x61\x74\x68"));
        const uint8_t *p = (const uint8_t *)in.base;
        err_desc = NULL;
        r = vhttp_hpack_decode_header(&pool, &header_table, &name, &value, &p, p + in.len, &err_desc);
        ok(r == 0);
        ok(name == &vhttp_TOKEN_PATH->buf);
        ok(value.len == 12);
        ok(strcmp(value.base, "/sample/path") == 0);
        ok(header_table.hpack_size == 0);
    }
    vhttp_mem_clear_pool(&pool);

    note("decode_header (literal header field never indexed)");
    {
        vhttp_hpack_header_table_t header_table;
        vhttp_iovec_t in, *name, value;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = vhttp_iovec_init(vhttp_STRLIT("\x10\x08\x70\x61\x73\x73\x77\x6f\x72\x64\x06\x73\x65\x63\x72\x65\x74"));
        const uint8_t *p = (const uint8_t *)in.base;
        err_desc = NULL;
        r = vhttp_hpack_decode_header(&pool, &header_table, &name, &value, &p, p + in.len, &err_desc);
        ok(r == 0);
        ok(name->len == 8);
        ok(strcmp(name->base, "password") == 0);
        ok(value.len == 6);
        ok(strcmp(value.base, "secret") == 0);
        ok(header_table.hpack_size == 0);
    }
    vhttp_mem_clear_pool(&pool);

    note("decode_header (indexed header field)");
    {
        vhttp_hpack_header_table_t header_table;
        vhttp_iovec_t in, *name, value;
        int r;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 4096;
        in = vhttp_iovec_init(vhttp_STRLIT("\x82"));
        const uint8_t *p = (const uint8_t *)in.base;
        err_desc = NULL;
        r = vhttp_hpack_decode_header(&pool, &header_table, &name, &value, &p, p + in.len, &err_desc);
        ok(r == 0);
        ok(name == &vhttp_TOKEN_METHOD->buf);
        ok(value.len == 3);
        ok(strcmp(value.base, "GET") == 0);
        ok(header_table.hpack_size == 0);
    }
    vhttp_mem_clear_pool(&pool);

    note("request examples without huffman coding");
    test_request(vhttp_iovec_init(vhttp_STRLIT("\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d")),
                 vhttp_iovec_init(vhttp_STRLIT("\x82\x86\x84\xbe\x58\x08\x6e\x6f\x2d\x63\x61\x63\x68\x65")),
                 vhttp_iovec_init(vhttp_STRLIT("\x82\x87\x85\xbf\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0c\x63\x75\x73\x74"
                                           "\x6f\x6d\x2d\x76\x61\x6c\x75\x65")));

    note("request examples with huffman coding");
    test_request(vhttp_iovec_init(vhttp_STRLIT("\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")),
                 vhttp_iovec_init(vhttp_STRLIT("\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf")),
                 vhttp_iovec_init(vhttp_STRLIT(
                     "\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf")));

    note("encode_huffman");
    {
        vhttp_iovec_t huffcode = {vhttp_STRLIT("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")};
        char buf[sizeof("www.example.com")];
        size_t l = vhttp_hpack_encode_huffman((uint8_t *)buf, (uint8_t *)vhttp_STRLIT("www.example.com"));
        ok(l == huffcode.len);
        ok(memcmp(buf, huffcode.base, huffcode.len) == 0);
    }

    note("response examples with huffmann coding");
    {
        vhttp_hpack_header_table_t header_table;
        vhttp_res_t res;

        memset(&header_table, 0, sizeof(header_table));
        header_table.hpack_capacity = 256;

        memset(&res, 0, sizeof(res));
        res.status = 302;
        res.reason = "Found";
        vhttp_add_header(&pool, &res.headers, vhttp_TOKEN_CACHE_CONTROL, NULL, vhttp_STRLIT("private"));
        vhttp_add_header(&pool, &res.headers, vhttp_TOKEN_DATE, NULL, vhttp_STRLIT("Mon, 21 Oct 2013 20:13:21 GMT"));
        vhttp_add_header(&pool, &res.headers, vhttp_TOKEN_LOCATION, NULL, vhttp_STRLIT("https://www.example.com"));
        check_flatten(&header_table, &res,
                      vhttp_STRLIT("\x08\x03\x33\x30\x32\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10"
                                 "\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91"
                                 "\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3"));

        memset(&res, 0, sizeof(res));
        res.status = 307;
        res.reason = "Temporary Redirect";
        vhttp_add_header(&pool, &res.headers, vhttp_TOKEN_CACHE_CONTROL, NULL, vhttp_STRLIT("private"));
        vhttp_add_header(&pool, &res.headers, vhttp_TOKEN_DATE, NULL, vhttp_STRLIT("Mon, 21 Oct 2013 20:13:21 GMT"));
        vhttp_add_header(&pool, &res.headers, vhttp_TOKEN_LOCATION, NULL, vhttp_STRLIT("https://www.example.com"));
        check_flatten(&header_table, &res, vhttp_STRLIT("\x08\x03\x33\x30\x37\xc0\xbf\xbe"));
#if 0
        vhttp_iovec_init(vhttp_STRLIT("\x48\x03\x33\x30\x37\xc1\xc0\xbf")),
        vhttp_iovec_init(vhttp_STRLIT("\x88\xc1\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x32\x20\x47\x4d\x54\xc0\x5a\x04\x67\x7a\x69\x70\x77\x38\x66\x6f\x6f\x3d\x41\x53\x44\x4a\x4b\x48\x51\x4b\x42\x5a\x58\x4f\x51\x57\x45\x4f\x50\x49\x55\x41\x58\x51\x57\x45\x4f\x49\x55\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x33\x36\x30\x30\x3b\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31")));
#endif
    }

    vhttp_mem_clear_pool(&pool);
}

static void parse_and_compare_request(vhttp_hpack_header_table_t *ht, const char *promise_base, size_t promise_len,
                                      vhttp_iovec_t expected_method, const vhttp_url_scheme_t *expected_scheme,
                                      vhttp_iovec_t expected_authority, vhttp_iovec_t expected_path, ...)
{
    vhttp_req_t req = {NULL};
    vhttp_mem_init_pool(&req.pool);

    int pseudo_header_exists_map = 0;
    size_t content_length = SIZE_MAX;
    vhttp_iovec_t expect = vhttp_iovec_init(NULL, 0);
    const char *err_desc = NULL;
    int r = vhttp_hpack_parse_request(&req.pool, vhttp_hpack_decode_header, ht, &req.input.method, &req.input.scheme,
                                    &req.input.authority, &req.input.path, &req.upgrade, &req.headers, &pseudo_header_exists_map,
                                    &content_length, &expect, NULL, NULL, (void *)(promise_base + 13), promise_len - 13, &err_desc);
    ok(r == 0);
    ok(vhttp_memis(req.input.method.base, req.input.method.len, expected_method.base, expected_method.len));
    ok(req.input.scheme == expected_scheme);
    ok(vhttp_memis(req.input.authority.base, req.input.authority.len, expected_authority.base, expected_authority.len));
    ok(vhttp_memis(req.input.path.base, req.input.path.len, expected_path.base, expected_path.len));

    va_list args;
    va_start(args, expected_path);
    size_t i;
    for (i = 0; i != req.headers.size; ++i) {
        vhttp_iovec_t expected_name = va_arg(args, vhttp_iovec_t);
        if (expected_name.base == NULL)
            break;
        vhttp_iovec_t expected_value = va_arg(args, vhttp_iovec_t);
        ok(vhttp_memis(req.headers.entries[i].name->base, req.headers.entries[i].name->len, expected_name.base, expected_name.len));
        ok(vhttp_memis(req.headers.entries[i].value.base, req.headers.entries[i].value.len, expected_value.base, expected_value.len));
    }
    ok(i == req.headers.size);
    va_end(args);

    vhttp_mem_clear_pool(&req.pool);
}

static void test_hpack_push(void)
{
    const static vhttp_iovec_t method = {vhttp_STRLIT("GET")}, authority = {vhttp_STRLIT("example.com")},
                             user_agent = {vhttp_STRLIT(
                                 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:40.0) Gecko/20100101 Firefox/40.0")},
                             accept_root = {vhttp_STRLIT("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")},
                             accept_images = {vhttp_STRLIT("image/png,image/*;q=0.8,*/*;q=0.5")},
                             accept_language = {vhttp_STRLIT("ja,en-US;q=0.7,en;q=0.3")},
                             accept_encoding = {vhttp_STRLIT("gzip, deflate")}, referer = {vhttp_STRLIT("https://example.com/")};

    vhttp_hpack_header_table_t encode_table = {NULL}, decode_table = {NULL};
    encode_table.hpack_capacity = decode_table.hpack_capacity = 4096;
    vhttp_req_t req = {NULL};
    vhttp_mem_init_pool(&req.pool);
    vhttp_buffer_t *buf;
    vhttp_buffer_init(&buf, &vhttp_socket_buffer_prototype);

    /* setup first request */
    req.input.method = method;
    req.input.scheme = &vhttp_URL_SCHEME_HTTPS;
    req.input.authority = authority;
    req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_USER_AGENT, NULL, user_agent.base, user_agent.len);
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_ACCEPT, NULL, accept_root.base, accept_root.len);
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_ACCEPT_LANGUAGE, NULL, accept_language.base, accept_language.len);
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_ACCEPT_ENCODING, NULL, accept_encoding.base, accept_encoding.len);

    /* serialize, deserialize, and compare */
    vhttp_hpack_flatten_push_promise(&buf, &encode_table, vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size, 0, 16384, req.input.scheme,
                                   req.input.authority, req.input.method, req.input.path, req.headers.entries, req.headers.size, 0);
    parse_and_compare_request(&decode_table, buf->bytes, buf->size, method, &vhttp_URL_SCHEME_HTTPS, authority,
                              vhttp_iovec_init(vhttp_STRLIT("/")), vhttp_TOKEN_USER_AGENT->buf, user_agent, vhttp_TOKEN_ACCEPT->buf,
                              accept_root, vhttp_TOKEN_ACCEPT_LANGUAGE->buf, accept_language, vhttp_TOKEN_ACCEPT_ENCODING->buf,
                              accept_encoding, (vhttp_iovec_t){NULL});
    vhttp_buffer_consume(&buf, buf->size);

    /* setup second request */
    req.input.path = vhttp_iovec_init(vhttp_STRLIT("/banner.jpg"));
    req.headers = (vhttp_headers_t){NULL};
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_USER_AGENT, NULL, user_agent.base, user_agent.len);
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_ACCEPT, NULL, accept_images.base, accept_images.len);
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_ACCEPT_LANGUAGE, NULL, accept_language.base, accept_language.len);
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_ACCEPT_ENCODING, NULL, accept_encoding.base, accept_encoding.len);
    vhttp_add_header(&req.pool, &req.headers, vhttp_TOKEN_REFERER, NULL, referer.base, referer.len);

    /* serialize, deserialize, and compare */
    vhttp_hpack_flatten_push_promise(&buf, &encode_table, vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size, 0, 16384, req.input.scheme,
                                   req.input.authority, req.input.method, req.input.path, req.headers.entries, req.headers.size, 0);
    parse_and_compare_request(
        &decode_table, buf->bytes, buf->size, method, &vhttp_URL_SCHEME_HTTPS, authority, vhttp_iovec_init(vhttp_STRLIT("/banner.jpg")),
        vhttp_TOKEN_USER_AGENT->buf, user_agent, vhttp_TOKEN_ACCEPT->buf, accept_images, vhttp_TOKEN_ACCEPT_LANGUAGE->buf,
        accept_language, vhttp_TOKEN_ACCEPT_ENCODING->buf, accept_encoding, vhttp_TOKEN_REFERER->buf, referer, (vhttp_iovec_t){NULL});
    vhttp_buffer_consume(&buf, buf->size);

    /* setup third request (headers are the same) */
    req.input.path = vhttp_iovec_init(vhttp_STRLIT("/icon.png"));

    /* serialize, deserialize, and compare */
    vhttp_hpack_flatten_push_promise(&buf, &encode_table, vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size, 0, 16384, req.input.scheme,
                                   req.input.authority, req.input.method, req.input.path, req.headers.entries, req.headers.size, 0);
    parse_and_compare_request(&decode_table, buf->bytes, buf->size, method, &vhttp_URL_SCHEME_HTTPS, authority,
                              vhttp_iovec_init(vhttp_STRLIT("/icon.png")), vhttp_TOKEN_USER_AGENT->buf, user_agent, vhttp_TOKEN_ACCEPT->buf,
                              accept_images, vhttp_TOKEN_ACCEPT_LANGUAGE->buf, accept_language, vhttp_TOKEN_ACCEPT_ENCODING->buf,
                              accept_encoding, vhttp_TOKEN_REFERER->buf, referer, (vhttp_iovec_t){NULL});
    vhttp_buffer_consume(&buf, buf->size);

    vhttp_buffer_dispose(&buf);
    vhttp_mem_clear_pool(&req.pool);
}

static void test_hpack_dynamic_table(void)
{
    vhttp_hpack_header_table_t header_table;
    uint8_t encoded[256], *p;
    vhttp_iovec_t n, v;

    memset(&header_table, 0, sizeof(header_table));
    header_table.hpack_capacity = 4096;

    p = encoded;
    /* expected: literal header with incremental indexing (name not indexed) */
    n = vhttp_iovec_init(vhttp_STRLIT("x-name"));
    v = vhttp_iovec_init(vhttp_STRLIT("v1"));
    p = do_encode_header(&header_table, p, &n, &v, 0);
    /* expected: literal header with incremental indexing (name indexed) */
    v = vhttp_iovec_init(vhttp_STRLIT("v2"));
    p = do_encode_header(&header_table, p, &n, &v, 0);
    /* expected: literal header with incremental indexing (name indexed, referring to the name associated with v2) */
    v = vhttp_iovec_init(vhttp_STRLIT("v3"));
    p = do_encode_header(&header_table, p, &n, &v, 0);
    /* expected: indexed header field */
    v = vhttp_iovec_init(vhttp_STRLIT("v1"));
    p = do_encode_header(&header_table, p, &n, &v, 0);

    const vhttp_iovec_t expected = vhttp_iovec_init(
        vhttp_STRLIT("\x40\x85"             /* literal header with incremental indexing (name not indexed, 5 bytes, huffman coded) */
                   "\xf2\xb5\x43\xa4\xbf" /* "x-name" */
                   "\x02"                 /* value not compressed, 2 bytes */
                   "v1"                   /* "v1" */
                   "\x7e"                 /* literal header with incremental indexing (name indexed) */
                   "\x02"                 /* value not compressed, 2 bytes */
                   "v2"                   /* "v2" */
                   "\x7e"                 /* literal header with incremental indexing (name indexed, referring to the last entry) */
                   "\x02"                 /* value not compressed, 2 bytes */
                   "v3"                   /* "v3" */
                   "\xc0"                 /* indexed header field */
                   ));
    ok(p - encoded == expected.len);
    ok(memcmp(encoded, expected.base, expected.len) == 0);
}

static void test_token_wo_hpack_id(void)
{
    vhttp_mem_pool_t pool;
    vhttp_mem_init_pool(&pool);
    vhttp_hpack_header_table_t table = {NULL};
    table.hpack_capacity = 4096;
    vhttp_res_t res = {0};
    vhttp_buffer_t *buf;
    vhttp_buffer_init(&buf, &vhttp_socket_buffer_prototype);

    res.status = 200;
    res.reason = "OK";
    vhttp_add_header(&pool, &res.headers, vhttp_TOKEN_TE, NULL, vhttp_STRLIT("test"));

    vhttp_hpack_flatten_response(&buf, &table, vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size, 1,
                               vhttp_HTTP2_SETTINGS_DEFAULT.max_frame_size, res.status, res.headers.entries, res.headers.size, NULL,
                               SIZE_MAX, 0);
    ok(vhttp_memis(buf->bytes + 9, buf->size - 9,
                 vhttp_STRLIT("\x88"     /* :status:200 */
                            "\x40\x02" /* literal header w. incremental indexing, raw, TE */
                            "te"
                            "\x83" /* header value, huffman */
                            "IP\x9f" /* test */)));
    vhttp_buffer_consume(&buf, buf->size);
    vhttp_hpack_flatten_response(&buf, &table, vhttp_HTTP2_SETTINGS_DEFAULT.header_table_size, 1,
                               vhttp_HTTP2_SETTINGS_DEFAULT.max_frame_size, res.status, res.headers.entries, res.headers.size, NULL,
                               SIZE_MAX, 0);
    ok(vhttp_memis(buf->bytes + 9, buf->size - 9,
                 vhttp_STRLIT("\x88" /* :status:200 */
                            "\xbe" /* te: test, indexed */)));

    vhttp_buffer_dispose(&buf);
    vhttp_hpack_dispose_header_table(&table);
    vhttp_mem_clear_pool(&pool);
}

static void do_test_inherit_invalid(vhttp_iovec_t first_input, vhttp_iovec_t second_input, vhttp_iovec_t expected_name,
                                    vhttp_iovec_t expected_first_value, const char *expected_first_err_desc,
                                    vhttp_iovec_t expected_second_value, const char *expected_second_err_desc)
{
    vhttp_mem_pool_t pool;
    vhttp_hpack_header_table_t table = {.hpack_capacity = 4096};

    vhttp_mem_init_pool(&pool);

    { /* add header with invalid name, valid value */
        int status;
        vhttp_headers_t headers = {};
        const char *err_desc = NULL;
        int ret = vhttp_hpack_parse_response(&pool, vhttp_hpack_decode_header, &table, &status, &headers, NULL,
                                           (const uint8_t *)first_input.base, first_input.len, &err_desc);
        ok(ret == vhttp_HTTP2_ERROR_INVALID_HEADER_CHAR);
        ok(err_desc == expected_first_err_desc);
        ok(status == 200);
        ok(headers.size == 1);
        ok(vhttp_memis(headers.entries[0].name->base, headers.entries[0].name->len, expected_name.base, expected_name.len));
        ok(vhttp_memis(headers.entries[0].value.base, headers.entries[0].value.len, expected_first_value.base,
                     expected_first_value.len));
    }

    { /* check that the invalid_name is inherited */
        int status;
        vhttp_headers_t headers = {};
        const char *err_desc = NULL;
        int ret = vhttp_hpack_parse_response(&pool, vhttp_hpack_decode_header, &table, &status, &headers, NULL,
                                           (const uint8_t *)second_input.base, second_input.len, &err_desc);
        if (expected_second_err_desc == NULL) {
            ok(ret == 0);
        } else {
            ok(ret == vhttp_HTTP2_ERROR_INVALID_HEADER_CHAR);
            ok(err_desc == expected_second_err_desc);
        }
        ok(status == 200);
        ok(headers.size == 1);
        ok(vhttp_memis(headers.entries[0].name->base, headers.entries[0].name->len, expected_name.base, expected_name.len));
        ok(vhttp_memis(headers.entries[0].value.base, headers.entries[0].value.len, expected_second_value.base,
                     expected_second_value.len));
    }

    vhttp_mem_clear_pool(&pool);
}

static void test_inherit_invalid(void)
{
    { /* inherit invalid name */
        static const uint8_t first_input[] = {
            0x88,                           /* :status: 200 */
            0x40, 3, 'a', '\n', 'b', 1, '0' /* a\nb: 0 */
        };
        static const uint8_t second_input[] = {
            0x88,        /* :status: 200 */
            0x7e, 1, '1' /* a\nb: 1 */
        };
        do_test_inherit_invalid(vhttp_iovec_init(first_input, sizeof(first_input)),
                                vhttp_iovec_init(second_input, sizeof(second_input)), vhttp_iovec_init(vhttp_STRLIT("a\nb")),
                                vhttp_iovec_init(vhttp_STRLIT("0")), vhttp_hpack_soft_err_found_invalid_char_in_header_name,
                                vhttp_iovec_init(vhttp_STRLIT("1")), vhttp_hpack_soft_err_found_invalid_char_in_header_name);
    }

    { /* inherit invalid name & value */
        static const uint8_t first_input[] = {
            0x88,                                      /* :status: 200 */
            0x40, 3, 'a', '\n', 'b', 3, '0', '\n', '1' /* a\nb: 0\n1 */
        };
        static const uint8_t second_input[] = {
            0x88,        /* :status: 200 */
            0x7e, 1, '1' /* a\nb: 1 */
        };
        do_test_inherit_invalid(vhttp_iovec_init(first_input, sizeof(first_input)),
                                vhttp_iovec_init(second_input, sizeof(second_input)), vhttp_iovec_init(vhttp_STRLIT("a\nb")),
                                vhttp_iovec_init(vhttp_STRLIT("0\n1")), vhttp_hpack_soft_err_found_invalid_char_in_header_name,
                                vhttp_iovec_init(vhttp_STRLIT("1")), vhttp_hpack_soft_err_found_invalid_char_in_header_name);
    }

    { /* do not inherit invalid value */
        static const uint8_t first_input[] = {
            0x88,                           /* :status: 200 */
            0x40, 1, 'a', 3, '0', '\n', '1' /* a: 0\n1 */
        };
        static const uint8_t second_input[] = {
            0x88,        /* :status: 200 */
            0x7e, 1, '1' /* a: 1 */
        };
        do_test_inherit_invalid(vhttp_iovec_init(first_input, sizeof(first_input)),
                                vhttp_iovec_init(second_input, sizeof(second_input)), vhttp_iovec_init(vhttp_STRLIT("a")),
                                vhttp_iovec_init(vhttp_STRLIT("0\n1")), vhttp_hpack_soft_err_found_invalid_char_in_header_value,
                                vhttp_iovec_init(vhttp_STRLIT("1")), NULL);
    }
}

static void test_dynamic_table_size_update(void)
{
    vhttp_hpack_header_table_t encoder = {}, decoder = {};
    encoder.hpack_capacity = encoder.hpack_max_capacity = decoder.hpack_capacity = decoder.hpack_max_capacity = 4096;
    vhttp_buffer_t *buf;
    vhttp_buffer_init(&buf, &vhttp_socket_buffer_prototype);
    vhttp_mem_pool_t pool;
    vhttp_mem_init_pool(&pool);
    vhttp_headers_t headers = {};
    const char *err_desc = NULL;
    int status, ret;

    /* first response */
    vhttp_hpack_flatten_response(&buf, &encoder, 1024, 1, vhttp_HTTP2_SETTINGS_DEFAULT.max_frame_size, 200, NULL, 0, NULL, 12345, 0);
    ret = vhttp_hpack_parse_response(&pool, vhttp_hpack_decode_header, &decoder, &status, &headers, NULL, (uint8_t *)buf->bytes + 9,
                                   buf->size - 9, &err_desc);
    ok(ret == 0);
    ok(decoder.hpack_capacity == 1024); /* check that capacity has changed */
    ok(status == 200);
    ok(headers.size == 1);
    ok(headers.entries[0].name == &vhttp_TOKEN_CONTENT_LENGTH->buf);
    ok(vhttp_memis(headers.entries[0].value.base, headers.entries[0].value.len, vhttp_STRLIT("12345")));

    vhttp_mem_clear_pool(&pool);
    vhttp_buffer_dispose(&buf);
}

static void do_test_more_soft_error(const uint8_t *src, size_t len, int is_header_name, vhttp_iovec_t expected_result)
{
    vhttp_mem_pool_t pool;
    unsigned soft_errors = 0;
    const char *err_desc = NULL;
    vhttp_iovec_t *result;

    vhttp_mem_init_pool(&pool);

    result = decode_string(&pool, &soft_errors, &src, src + len, is_header_name, &err_desc);
    ok(result != NULL);
    ok(vhttp_memis(result->base, result->len, expected_result.base, expected_result.len));
    ok(soft_errors == (is_header_name ? vhttp_HPACK_SOFT_ERROR_BIT_INVALID_NAME : vhttp_HPACK_SOFT_ERROR_BIT_INVALID_VALUE));
    ok(err_desc == NULL);

    vhttp_mem_clear_pool(&pool);
}

static void test_more_soft_errors(void)
{
    note("empty header name, huffman");
    do_test_more_soft_error((const uint8_t[]){0x80}, 1, 1, vhttp_iovec_init(vhttp_STRLIT("")));
    note("empty header name, no huffman");
    do_test_more_soft_error((const uint8_t[]){0x00}, 1, 1, vhttp_iovec_init(vhttp_STRLIT("")));

    /* whitespace around header values; see RFC 9113 8.2.1 */
    note("header value w. preceding whitespace, huffman");
    do_test_more_soft_error((const uint8_t[]){0x83, 0x50, 0x71, 0xff}, 4, 0, vhttp_iovec_init(vhttp_STRLIT(" ab")));
    do_test_more_soft_error((const uint8_t[]){0x85, 0xff, 0xff, 0xea, 0x1c, 0x7f}, 6, 0, vhttp_iovec_init(vhttp_STRLIT("\tab")));
    do_test_more_soft_error((const uint8_t[]){0x83, 0x1c, 0x6a, 0x7f}, 4, 0, vhttp_iovec_init(vhttp_STRLIT("ab ")));
    note("header value w. preceding whitespace, no huffman");
    do_test_more_soft_error((const uint8_t[]){0x03, 0x20, 'a', 'b'}, 4, 0, vhttp_iovec_init(vhttp_STRLIT(" ab")));
    do_test_more_soft_error((const uint8_t[]){0x03, 0x09, 'a', 'b'}, 4, 0, vhttp_iovec_init(vhttp_STRLIT("\tab")));
    do_test_more_soft_error((const uint8_t[]){0x03, 'a', 'b', 0x20}, 4, 0, vhttp_iovec_init(vhttp_STRLIT("ab ")));
}

void test_lib__http2__hpack(void)
{
    subtest("hpack", test_hpack);
    subtest("hpack-push", test_hpack_push);
    subtest("hpack-dynamic-table", test_hpack_dynamic_table);
    subtest("token-wo-hpack-id", test_token_wo_hpack_id);
    subtest("inherit-invalid", test_inherit_invalid);
    subtest("dynamic-table-size-update", test_dynamic_table_size_update);
    subtest("empty-header-name", test_more_soft_errors);
}
