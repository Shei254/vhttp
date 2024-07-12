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
#include "../../../../lib/core/proxy.c"

static void test_rewrite_location(void)
{
    vhttp_url_t upstream;
    vhttp_mem_pool_t pool;
    vhttp_iovec_t ret;
    vhttp_mem_init_pool(&pool);

    vhttp_url_parse(&pool, vhttp_STRLIT("http://realhost:81/real/"), &upstream);

    ret = rewrite_location(&pool, vhttp_STRLIT("http://realhost:81/real/abc"), &upstream, &vhttp_URL_SCHEME_HTTPS,
                           vhttp_iovec_init(vhttp_STRLIT("vhost:8443")), vhttp_iovec_init(vhttp_STRLIT("/virtual/")));
    ok(vhttp_memis(ret.base, ret.len, vhttp_STRLIT("https://vhost:8443/virtual/abc")));
    ret = rewrite_location(&pool, vhttp_STRLIT("http://realhost:81/other/abc"), &upstream, &vhttp_URL_SCHEME_HTTPS,
                           vhttp_iovec_init(vhttp_STRLIT("vhost:8443")), vhttp_iovec_init(vhttp_STRLIT("/virtual/")));
    ok(ret.base == NULL);
    ok(ret.len == 0);

    vhttp_mem_clear_pool(&pool);
}

void test_lib__core__proxy_c()
{
    subtest("rewrite_location", test_rewrite_location);
}
