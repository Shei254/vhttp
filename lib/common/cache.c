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
#include <assert.h>
#include <pthread.h>
#include "khash.h"
#include "vhttp/cache.h"
#include "vhttp/linklist.h"
#include "vhttp/memory.h"
#include "vhttp/string_.h"

static vhttp_cache_hashcode_t get_keyhash(vhttp_cache_ref_t *ref);
static int is_equal(vhttp_cache_ref_t *x, vhttp_cache_ref_t *y);

KHASH_INIT(cache, vhttp_cache_ref_t *, char, 0, get_keyhash, is_equal)

struct st_vhttp_cache_t {
    int flags;
    khash_t(cache) * table;
    size_t size;
    size_t capacity;
    vhttp_linklist_t lru;
    vhttp_linklist_t age;
    uint64_t duration;
    void (*destroy_cb)(vhttp_iovec_t value);
    pthread_mutex_t mutex; /* only used if (flags & vhttp_CACHE_FLAG_MULTITHREADED) != 0 */
};

static vhttp_cache_hashcode_t get_keyhash(vhttp_cache_ref_t *ref)
{
    return ref->keyhash;
}

static int is_equal(vhttp_cache_ref_t *x, vhttp_cache_ref_t *y)
{
    return x->key.len == y->key.len && memcmp(x->key.base, y->key.base, x->key.len) == 0;
}

static void lock_cache(vhttp_cache_t *cache)
{
    if ((cache->flags & vhttp_CACHE_FLAG_MULTITHREADED) != 0)
        pthread_mutex_lock(&cache->mutex);
}

static void unlock_cache(vhttp_cache_t *cache)
{
    if ((cache->flags & vhttp_CACHE_FLAG_MULTITHREADED) != 0)
        pthread_mutex_unlock(&cache->mutex);
}

static void erase_ref(vhttp_cache_t *cache, khiter_t iter, int reuse)
{
    vhttp_cache_ref_t *ref = kh_key(cache->table, iter);

    if (!reuse)
        kh_del(cache, cache->table, iter);
    vhttp_linklist_unlink(&ref->_lru_link);
    vhttp_linklist_unlink(&ref->_age_link);
    cache->size -= ref->value.len;

    vhttp_cache_release(cache, ref);
}

static int64_t get_timeleft(vhttp_cache_t *cache, vhttp_cache_ref_t *ref, uint64_t now)
{
    return (int64_t)(ref->at + cache->duration) - now;
}

static void purge(vhttp_cache_t *cache, uint64_t now)
{
    /* by cache size */
    while (cache->capacity < cache->size) {
        vhttp_cache_ref_t *last;
        assert(!vhttp_linklist_is_empty(&cache->lru));
        last = vhttp_STRUCT_FROM_MEMBER(vhttp_cache_ref_t, _lru_link, cache->lru.next);
        erase_ref(cache, kh_get(cache, cache->table, last), 0);
    }
    /* by TTL */
    while (!vhttp_linklist_is_empty(&cache->age)) {
        vhttp_cache_ref_t *oldest = vhttp_STRUCT_FROM_MEMBER(vhttp_cache_ref_t, _age_link, cache->age.next);
        if (get_timeleft(cache, oldest, now) >= 0)
            break;
        erase_ref(cache, kh_get(cache, cache->table, oldest), 0);
    }
}

vhttp_cache_hashcode_t vhttp_cache_calchash(const char *s, size_t l)
{
    vhttp_cache_hashcode_t h = 0;
    for (; l != 0; --l)
        h = (h << 5) - h + ((unsigned char *)s)[l - 1];
    return h;
}

vhttp_cache_t *vhttp_cache_create(int flags, size_t capacity, uint64_t duration, void (*destroy_cb)(vhttp_iovec_t value))
{
    vhttp_cache_t *cache = vhttp_mem_alloc(sizeof(*cache));

    cache->flags = flags;
    cache->table = kh_init(cache);
    cache->size = 0;
    cache->capacity = capacity;
    vhttp_linklist_init_anchor(&cache->lru);
    vhttp_linklist_init_anchor(&cache->age);
    cache->duration = duration;
    cache->destroy_cb = destroy_cb;
    if ((cache->flags & vhttp_CACHE_FLAG_MULTITHREADED) != 0)
        pthread_mutex_init(&cache->mutex, NULL);

    return cache;
}

void vhttp_cache_destroy(vhttp_cache_t *cache)
{
    vhttp_cache_clear(cache);
    kh_destroy(cache, cache->table);
    if ((cache->flags & vhttp_CACHE_FLAG_MULTITHREADED) != 0)
        pthread_mutex_destroy(&cache->mutex);
    free(cache);
}

void vhttp_cache_clear(vhttp_cache_t *cache)
{
    lock_cache(cache);

    while (!vhttp_linklist_is_empty(&cache->lru)) {
        vhttp_cache_ref_t *ref = vhttp_STRUCT_FROM_MEMBER(vhttp_cache_ref_t, _lru_link, cache->lru.next);
        erase_ref(cache, kh_get(cache, cache->table, ref), 0);
    }
    assert(vhttp_linklist_is_linked(&cache->age));
    assert(kh_size(cache->table) == 0);
    assert(cache->size == 0);

    unlock_cache(cache);
}

vhttp_cache_ref_t *vhttp_cache_fetch(vhttp_cache_t *cache, uint64_t now, vhttp_iovec_t key, vhttp_cache_hashcode_t keyhash)
{
    vhttp_cache_ref_t search_key, *ref;
    khiter_t iter;
    int64_t timeleft;

    if (keyhash == 0)
        keyhash = vhttp_cache_calchash(key.base, key.len);
    search_key.key = key;
    search_key.keyhash = keyhash;

    lock_cache(cache);

    purge(cache, now);

    if ((iter = kh_get(cache, cache->table, &search_key)) == kh_end(cache->table))
        goto NotFound;

    /* found */
    ref = kh_key(cache->table, iter);
    timeleft = get_timeleft(cache, ref, now);
    if (timeleft < 0)
        goto NotFound;
    if ((cache->flags & vhttp_CACHE_FLAG_EARLY_UPDATE) != 0 && timeleft < 10 && !ref->_requested_early_update) {
        ref->_requested_early_update = 1;
        goto NotFound;
    }
    /* move the entry to the top of LRU */
    vhttp_linklist_unlink(&ref->_lru_link);
    vhttp_linklist_insert(&cache->lru, &ref->_lru_link);
    __sync_fetch_and_add(&ref->_refcnt, 1);

    /* unlock and return the found entry */
    unlock_cache(cache);
    return ref;

NotFound:
    unlock_cache(cache);
    return NULL;
}

void vhttp_cache_release(vhttp_cache_t *cache, vhttp_cache_ref_t *ref)
{
    if (__sync_fetch_and_sub(&ref->_refcnt, 1) == 1) {
        assert(!vhttp_linklist_is_linked(&ref->_lru_link));
        assert(!vhttp_linklist_is_linked(&ref->_age_link));
        if (cache->destroy_cb != NULL)
            cache->destroy_cb(ref->value);
        free(ref->key.base);
        free(ref);
    }
}

int vhttp_cache_set(vhttp_cache_t *cache, uint64_t now, vhttp_iovec_t key, vhttp_cache_hashcode_t keyhash, vhttp_iovec_t value)
{
    vhttp_cache_ref_t *newref;
    khiter_t iter;
    int existed;

    if (keyhash == 0)
        keyhash = vhttp_cache_calchash(key.base, key.len);

    /* create newref */
    newref = vhttp_mem_alloc(sizeof(*newref));
    *newref = (vhttp_cache_ref_t){vhttp_strdup(NULL, key.base, key.len), keyhash, now, value, 0, {NULL}, {NULL}, 1};

    lock_cache(cache);

    /* set or replace the named value */
    iter = kh_get(cache, cache->table, newref);
    if (iter != kh_end(cache->table)) {
        erase_ref(cache, iter, 1);
        kh_key(cache->table, iter) = newref;
        existed = 1;
    } else {
        int unused;
        kh_put(cache, cache->table, newref, &unused);
        existed = 0;
    }
    vhttp_linklist_insert(&cache->lru, &newref->_lru_link);
    vhttp_linklist_insert(&cache->age, &newref->_age_link);
    cache->size += newref->value.len;

    purge(cache, now);

    unlock_cache(cache);

    return existed;
}

void vhttp_cache_delete(vhttp_cache_t *cache, uint64_t now, vhttp_iovec_t key, vhttp_cache_hashcode_t keyhash)
{
    vhttp_cache_ref_t search_key;
    khiter_t iter;

    if (keyhash == 0)
        keyhash = vhttp_cache_calchash(key.base, key.len);
    search_key.key = key;
    search_key.keyhash = keyhash;

    lock_cache(cache);

    purge(cache, now);

    if ((iter = kh_get(cache, cache->table, &search_key)) != kh_end(cache->table))
        erase_ref(cache, iter, 0);

    unlock_cache(cache);
}

size_t vhttp_cache_get_capacity(vhttp_cache_t *cache)
{
    return cache->capacity;
}

uint64_t vhttp_cache_get_duration(vhttp_cache_t *cache)
{
    return cache->duration;
}
