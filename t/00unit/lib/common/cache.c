/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku
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
#include "../../../../lib/common/cache.c"

static size_t bytes_destroyed;

static void on_destroy(vhttp_iovec_t vec)
{
    bytes_destroyed += vec.len;
}

void test_lib__common__cache_c(void)
{
    vhttp_cache_t *cache = vhttp_cache_create(vhttp_CACHE_FLAG_EARLY_UPDATE, 1024, 1000, on_destroy);
    uint64_t now = 0;
    vhttp_iovec_t key = {vhttp_STRLIT("key")};
    vhttp_cache_ref_t *ref;

    /* fetch "key" */
    ref = vhttp_cache_fetch(cache, now, key, 0);
    ok(ref == NULL);

    /* set "key" => "value" */
    vhttp_cache_set(cache, now, key, 0, vhttp_iovec_init(vhttp_STRLIT("value")));

    /* delete "key" */
    vhttp_cache_delete(cache, now, key, 0);
    ref = vhttp_cache_fetch(cache, now, key, 0);
    ok(ref == NULL);

    /* set "key" => "value" */
    vhttp_cache_set(cache, now, key, 0, vhttp_iovec_init(vhttp_STRLIT("value")));

    /* fetch "key" */
    ref = vhttp_cache_fetch(cache, now, key, 0);
    ok(vhttp_memis(ref->value.base, ref->value.len, vhttp_STRLIT("value")));
    vhttp_cache_release(cache, ref);

    /* proceed 999ms */
    now += 999;

    /* should fail to fetch "key" */
    ref = vhttp_cache_fetch(cache, now, key, 0);
    ok(ref == NULL);

    /* refetch should succeed */
    ref = vhttp_cache_fetch(cache, now, key, 0);
    ok(vhttp_memis(ref->value.base, ref->value.len, vhttp_STRLIT("value")));
    vhttp_cache_release(cache, ref);

    /* set "key" to "value2" */
    vhttp_cache_set(cache, now, key, 0, vhttp_iovec_init(vhttp_STRLIT("value2")));

    /* fetch */
    ref = vhttp_cache_fetch(cache, now, key, 0);
    ok(vhttp_memis(ref->value.base, ref->value.len, vhttp_STRLIT("value2")));
    vhttp_cache_release(cache, ref);

    ok(bytes_destroyed == 10);

    vhttp_cache_destroy(cache);

    ok(bytes_destroyed == 16);
}
