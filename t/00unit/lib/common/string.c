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
#include "../../test.h"
#include "../../../../lib/common/string.c"

static void test_strstr(void)
{
    ok(vhttp_strstr("abcd", 4, "bc", 2) == 1);
    ok(vhttp_strstr("abcd", 3, "bc", 2) == 1);
    ok(vhttp_strstr("abcd", 2, "bc", 2) == -1);
}

static void test_stripws(void)
{
    vhttp_iovec_t t;

    t = vhttp_str_stripws(vhttp_STRLIT(""));
    ok(vhttp_memis(t.base, t.len, vhttp_STRLIT("")));
    t = vhttp_str_stripws(vhttp_STRLIT("hello world"));
    ok(vhttp_memis(t.base, t.len, vhttp_STRLIT("hello world")));
    t = vhttp_str_stripws(vhttp_STRLIT("   hello world"));
    ok(vhttp_memis(t.base, t.len, vhttp_STRLIT("hello world")));
    t = vhttp_str_stripws(vhttp_STRLIT("hello world   "));
    ok(vhttp_memis(t.base, t.len, vhttp_STRLIT("hello world")));
    t = vhttp_str_stripws(vhttp_STRLIT("   hello world   "));
    ok(vhttp_memis(t.base, t.len, vhttp_STRLIT("hello world")));
    t = vhttp_str_stripws(vhttp_STRLIT("     "));
    ok(vhttp_memis(t.base, t.len, vhttp_STRLIT("")));
}

static void test_get_filext(void)
{
    vhttp_iovec_t ext;

    ext = vhttp_get_filext(vhttp_STRLIT("/abc.txt"));
    ok(vhttp_memis(ext.base, ext.len, vhttp_STRLIT("txt")));
    ext = vhttp_get_filext(vhttp_STRLIT("/abc.txt.gz"));
    ok(vhttp_memis(ext.base, ext.len, vhttp_STRLIT("gz")));
    ext = vhttp_get_filext(vhttp_STRLIT("/abc."));
    ok(vhttp_memis(ext.base, ext.len, vhttp_STRLIT("")));
    ext = vhttp_get_filext(vhttp_STRLIT("/abc"));
    ok(ext.base == NULL);
    ext = vhttp_get_filext(vhttp_STRLIT("/abc.def/abc"));
    ok(ext.base == NULL);
    ext = vhttp_get_filext(vhttp_STRLIT("/abc.def/"));
    ok(ext.base == NULL);
}

static void test_next_token(void)
{
    vhttp_iovec_t iter;
    const char *token;
    size_t token_len;

#define NEXT()                                                                                                                     \
    if ((token = vhttp_next_token(&iter, ',', ',', &token_len, NULL)) == NULL) {                                                     \
        ok(0);                                                                                                                     \
        return;                                                                                                                    \
    }

    iter = vhttp_iovec_init(vhttp_STRLIT("public, max-age=86400, must-revalidate"));
    NEXT();
    ok(vhttp_memis(token, token_len, vhttp_STRLIT("public")));
    NEXT();
    ok(vhttp_memis(token, token_len, vhttp_STRLIT("max-age=86400")));
    NEXT();
    ok(vhttp_memis(token, token_len, vhttp_STRLIT("must-revalidate")));
    token = vhttp_next_token(&iter, ',', ',', &token_len, NULL);
    ok(token == NULL);

    iter = vhttp_iovec_init(vhttp_STRLIT("  public  ,max-age=86400  ,"));
    NEXT();
    ok(vhttp_memis(token, token_len, vhttp_STRLIT("public")));
    NEXT();
    ok(vhttp_memis(token, token_len, vhttp_STRLIT("max-age=86400")));
    token = vhttp_next_token(&iter, ',', ',', &token_len, NULL);
    ok(token == NULL);

    iter = vhttp_iovec_init(vhttp_STRLIT(""));
    token = vhttp_next_token(&iter, ',', ',', &token_len, NULL);
    ok(token == NULL);

    iter = vhttp_iovec_init(vhttp_STRLIT(", ,a, "));
    NEXT();
    ok(token_len == 0);
    NEXT();
    ok(token_len == 0);
    NEXT();
    ok(vhttp_memis(token, token_len, vhttp_STRLIT("a")));
    token = vhttp_next_token(&iter, ',', ',', &token_len, NULL);
    ok(token == NULL);

#undef NEXT
}

static void test_next_token2(void)
{
    vhttp_iovec_t iter, value;
    const char *name;
    size_t name_len;

#define NEXT()                                                                                                                     \
    if ((name = vhttp_next_token(&iter, ',', ',', &name_len, &value)) == NULL) {                                                     \
        ok(0);                                                                                                                     \
        return;                                                                                                                    \
    }

    iter = vhttp_iovec_init(vhttp_STRLIT("public, max-age=86400, must-revalidate"));
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("public")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("max-age")));
    ok(vhttp_memis(value.base, value.len, vhttp_STRLIT("86400")));
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("must-revalidate")));
    ok(value.base == NULL);
    ok(value.len == 0);
    name = vhttp_next_token(&iter, ',', ',', &name_len, &value);
    ok(name == NULL);

    iter = vhttp_iovec_init(vhttp_STRLIT("public, max-age = 86400 = c , must-revalidate="));
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("public")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("max-age")));
    ok(vhttp_memis(value.base, value.len, vhttp_STRLIT("86400 = c")));
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("must-revalidate")));
    name = vhttp_next_token(&iter, ',', ',', &name_len, &value);
    ok(vhttp_memis(value.base, value.len, vhttp_STRLIT("")));

#undef NEXT
}

static void test_next_token3(void)
{
    vhttp_iovec_t iter, value;
    const char *name;
    size_t name_len;

#define NEXT()                                                                                                                     \
    if ((name = vhttp_next_token(&iter, ';', ',', &name_len, &value)) == NULL) {                                                     \
        ok(0);                                                                                                                     \
        return;                                                                                                                    \
    }

    iter = vhttp_iovec_init(vhttp_STRLIT("</foo.css>; rel=preload; xxx=,</bar.js>, </zzz.js>"));
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("</foo.css>")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("rel")));
    ok(vhttp_memis(value.base, value.len, vhttp_STRLIT("preload")));
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("xxx")));
    ok(value.base != NULL); /* xxx _has_ a value! */
    ok(value.len == 0);
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT(",")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("</bar.js>")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT(",")));
    ok(value.base == NULL);
    ok(value.len == 0);
    NEXT();
    ok(vhttp_memis(name, name_len, vhttp_STRLIT("</zzz.js>")));
    ok(value.base == NULL);
    ok(value.len == 0);
    name = vhttp_next_token(&iter, ',', ',', &name_len, &value);
    ok(name == NULL);

#undef NEXT
}

static void test_decode_base64(void)
{
    vhttp_mem_pool_t pool;
    char buf[256];

    vhttp_mem_init_pool(&pool);

    vhttp_iovec_t src = {vhttp_STRLIT("The quick brown fox jumps over the lazy dog.")}, decoded;
    vhttp_base64_encode(buf, (const uint8_t *)src.base, src.len, 1);
    ok(strcmp(buf, "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4") == 0);
    decoded = vhttp_decode_base64url(&pool, buf, strlen(buf));
    ok(src.len == decoded.len);
    ok(strcmp(decoded.base, src.base) == 0);

    vhttp_mem_clear_pool(&pool);
}

static void test_htmlescape(void)
{
    vhttp_mem_pool_t pool;
    vhttp_mem_init_pool(&pool);

#define TEST(src, expected)                                                                                                        \
    do {                                                                                                                           \
        vhttp_iovec_t escaped = vhttp_htmlescape(&pool, vhttp_STRLIT(src));                                                              \
        ok(vhttp_memis(escaped.base, escaped.len, vhttp_STRLIT(expected)));                                                            \
    } while (0)

    TEST("hello world", "hello world");
    TEST("x < y", "x &lt; y");
    TEST("\0\"&'<>", "\0&quot;&amp;&#39;&lt;&gt;");

#undef TEST

    vhttp_mem_clear_pool(&pool);
}

static void test_uri_escape(void)
{
    vhttp_mem_pool_t pool;
    vhttp_mem_init_pool(&pool);

#define TEST(src, preserve, expected)                                                                                              \
    do {                                                                                                                           \
        vhttp_iovec_t escaped = vhttp_uri_escape(&pool, vhttp_STRLIT(src), preserve);                                                    \
        ok(vhttp_memis(escaped.base, escaped.len, vhttp_STRLIT(expected)));                                                            \
    } while (0)

    TEST("abc", NULL, "abc");
    TEST("a/c", NULL, "a%2Fc");
    TEST("a/c", "/", "a/c");
    TEST("\xe3\x81\x82", NULL, "%E3%81%82");
    TEST("a\0!", NULL, "a%00!");
    TEST("a/\0!", "/", "a/%00!");

#undef TEST

    vhttp_mem_clear_pool(&pool);
}

static void test_uri_unescape(void)
{
    vhttp_mem_pool_t pool;
    vhttp_mem_init_pool(&pool);

#define TEST(src, block)                                                                                                           \
    do {                                                                                                                           \
        vhttp_iovec_t actual = vhttp_uri_unescape(&pool, vhttp_STRLIT(src));                                                             \
        {                                                                                                                          \
            block                                                                                                                  \
        }                                                                                                                          \
    } while (0)

    TEST("abc", {
        ok(vhttp_memis(actual.base, actual.len, vhttp_STRLIT("abc")));
        ok(actual.base[actual.len] == '\0');
    });
    TEST("a%0ac", {
        ok(vhttp_memis(actual.base, actual.len, vhttp_STRLIT("a\nc")));
        ok(actual.base[actual.len] == '\0');
    });
    TEST("a%xc", {
        ok(actual.base == NULL);
        ok(actual.len == 0);
    });
    TEST("a%0xc", {
        ok(actual.base == NULL);
        ok(actual.len == 0);
    });
    TEST("a%00c", {
        ok(actual.base == NULL);
        ok(actual.len == 0);
    });

#undef TEST
}

static void test_at_position(void)
{
    char buf[160];
    int ret;

    /* normal cases */
    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 1, 1);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n^\n") == 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 1, 5);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n    ^\n") == 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 1, 6);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n     ^\n") == 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 1, 7);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n     ^\n") == 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 2, 1);
    ok(ret == 0);
    ok(strcmp(buf, "world\n^\n") == 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 2, 5);
    ok(ret == 0);
    ok(strcmp(buf, "world\n    ^\n") == 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 1, 7);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n     ^\n") == 0);

    ret = vhttp_str_at_position(
        buf, vhttp_STRLIT("_________1_________2_________3_________4_________5_________6_________7_________\nworld\n"), 1, 5);
    ok(ret == 0);
    ok(strcmp(buf, "_________1_________2_________3_________4_________5_________6_________7______\n    ^\n") == 0);

    ret = vhttp_str_at_position(
        buf, vhttp_STRLIT("_________1_________2_________3_________4_________5_________6_________7_________\nworld\n"), 1, 60);
    ok(ret == 0);
    ok(strcmp(buf, "_________3_________4_________5_________6_________7_________\n                                       ^\n") == 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello"), 1, 20);
    ok(ret == 0);
    ok(strcmp(buf, "hello\n     ^\n") == 0);

    /* error cases */
    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 0, 1);
    ok(ret != 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 1, 0);
    ok(ret != 0);

    ret = vhttp_str_at_position(buf, vhttp_STRLIT("hello\nworld\n"), 4, 1);
    ok(ret != 0);
}

static void test_join_list(void)
{
    vhttp_mem_pool_t pool;
    vhttp_mem_init_pool(&pool);

    vhttp_iovec_t list[5] = {
        vhttp_iovec_init(vhttp_STRLIT("")),  vhttp_iovec_init(vhttp_STRLIT("a")), vhttp_iovec_init(vhttp_STRLIT("")),
        vhttp_iovec_init(vhttp_STRLIT("b")), vhttp_iovec_init(vhttp_STRLIT("")),
    };

    vhttp_iovec_t ret = vhttp_join_list(&pool, list, sizeof(list) / sizeof(list[0]), vhttp_iovec_init(vhttp_STRLIT("...")));
    ok(vhttp_memis(ret.base, ret.len, vhttp_STRLIT("...a......b...")));

    vhttp_mem_clear_pool(&pool);
}

static void test_split(void)
{
    vhttp_mem_pool_t pool;
    vhttp_mem_init_pool(&pool);

#define TEST(str, needle, ...)                                                                                                     \
    do {                                                                                                                           \
        const char *expected[] = {__VA_ARGS__};                                                                                    \
        vhttp_iovec_vector_t list = {0};                                                                                             \
        vhttp_split(&pool, &list, vhttp_iovec_init(vhttp_STRLIT((str))), (needle));                                                      \
        size_t expected_len = sizeof(expected) / sizeof(expected[0]);                                                              \
        ok(expected_len == list.size);                                                                                             \
        size_t i;                                                                                                                  \
        for (i = 0; i != list.size; ++i) {                                                                                         \
            ok(vhttp_memis(list.entries[i].base, list.entries[i].len, expected[i], strlen(expected[i])));                            \
        }                                                                                                                          \
    } while (0);

    TEST("foo*bar*baz", '*', "foo", "bar", "baz");
    TEST("***", '*', "", "", "", "");

    vhttp_mem_clear_pool(&pool);
}

void test_lib__common__string_c(void)
{
    subtest("strstr", test_strstr);
    subtest("stripws", test_stripws);
    subtest("get_filext", test_get_filext);
    subtest("next_token", test_next_token);
    subtest("next_token2", test_next_token2);
    subtest("next_token3", test_next_token3);
    subtest("decode_base64", test_decode_base64);
    subtest("htmlescape", test_htmlescape);
    subtest("uri_escape", test_uri_escape);
    subtest("uri_unescape", test_uri_unescape);
    subtest("at_position", test_at_position);
    subtest("join_list", test_join_list);
    subtest("split", test_split);
}
