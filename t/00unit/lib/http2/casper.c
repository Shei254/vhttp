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
#include <string.h>
#include "../../test.h"
#include "../../../../lib/http2/casper.c"

static size_t get_end_of_cookie_value(char *cookie, size_t cookie_len)
{
    size_t i;
    for (i = 0; i != cookie_len; ++i)
        if (cookie[i] == ';')
            break;
    return i;
}

static void test_calc_key(void)
{
    vhttp_http2_casper_t *casper = vhttp_http2_casper_create(13, 6);

    unsigned key = calc_key(casper, vhttp_STRLIT("/index.html")), expected;
    memcpy(&expected, "\x14\xfe\x45\x59", 4);
    expected &= (1 << 13) - 1;
    ok(key == expected);

    vhttp_http2_casper_destroy(casper);
}

static void test_lookup(void)
{
    vhttp_http2_casper_t *casper;
    casper = vhttp_http2_casper_create(13, 6);

    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 0) == 0);
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 1) == 0);
    ok(casper->keys.size == 1);
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 0) == 1);
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 1) == 1);
    ok(casper->keys.size == 1);

    vhttp_http2_casper_destroy(casper);
}

static void test_cookie(void)
{
    vhttp_http2_casper_t *casper;

    casper = vhttp_http2_casper_create(13, 6);

    vhttp_iovec_t cookie = vhttp_http2_casper_get_cookie(casper);
    ok(cookie.base == NULL);
    ok(cookie.len == 0);

    vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 1);
    cookie = vhttp_http2_casper_get_cookie(casper);
    ok(cookie.len != 0);
    cookie = vhttp_strdup(NULL, cookie.base, cookie.len);
    vhttp_http2_casper_destroy(casper);
    casper = vhttp_http2_casper_create(13, 6);

    vhttp_http2_casper_consume_cookie(casper, cookie.base, get_end_of_cookie_value(cookie.base, cookie.len));
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 0) == 1);
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.php"), 0) == 0);
    vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.php"), 1);

    vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 1);
    cookie = vhttp_http2_casper_get_cookie(casper);
    ok(cookie.len != 0);
    cookie = vhttp_strdup(NULL, cookie.base, cookie.len);

    vhttp_http2_casper_destroy(casper);
    casper = vhttp_http2_casper_create(13, 6);

    vhttp_http2_casper_consume_cookie(casper, cookie.base, get_end_of_cookie_value(cookie.base, cookie.len));
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 0) == 1);
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.php"), 0) == 1);

    vhttp_http2_casper_destroy(casper);
}

static void test_cookie_merge(void)
{
    vhttp_http2_casper_t *casper;

    casper = vhttp_http2_casper_create(13, 6);
    vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 1);
    vhttp_iovec_t cookie1 = vhttp_http2_casper_get_cookie(casper);
    cookie1 = vhttp_strdup(NULL, cookie1.base, cookie1.len);
    vhttp_http2_casper_destroy(casper);

    casper = vhttp_http2_casper_create(13, 6);
    vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.php"), 1);
    vhttp_iovec_t cookie2 = vhttp_http2_casper_get_cookie(casper);
    cookie2 = vhttp_strdup(NULL, cookie2.base, cookie2.len);
    vhttp_http2_casper_destroy(casper);

    casper = vhttp_http2_casper_create(13, 6);
    vhttp_http2_casper_consume_cookie(casper, cookie1.base, get_end_of_cookie_value(cookie1.base, cookie1.len));
    vhttp_http2_casper_consume_cookie(casper, cookie1.base, get_end_of_cookie_value(cookie1.base, cookie1.len));
    ok(casper->keys.size == 1);
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 0) == 1);
    vhttp_http2_casper_consume_cookie(casper, cookie2.base, get_end_of_cookie_value(cookie2.base, cookie2.len));
    ok(casper->keys.size == 2);
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.html"), 0) == 1);
    ok(vhttp_http2_casper_lookup(casper, vhttp_STRLIT("/index.php"), 0) == 1);
    vhttp_http2_casper_destroy(casper);
}

void test_lib__http2__casper(void)
{
    subtest("calc_key", test_calc_key);
    subtest("test_lookup", test_lookup);
    subtest("cookie", test_cookie);
    subtest("cookie-merge", test_cookie_merge);
}
