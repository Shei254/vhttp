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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include "khash.h"
#include "vhttp/memory.h"
#include "vhttp/filecache.h"

KHASH_SET_INIT_STR(opencache_set)

struct st_vhttp_filecache_t {
    khash_t(opencache_set) * hash;
    vhttp_linklist_t lru;
    size_t capacity;
};

static inline void release_from_cache(vhttp_filecache_t *cache, khiter_t iter)
{
    const char *path = kh_key(cache->hash, iter);
    vhttp_filecache_ref_t *ref = vhttp_STRUCT_FROM_MEMBER(vhttp_filecache_ref_t, _path, path);

    /* detach from list */
    kh_del(opencache_set, cache->hash, iter);
    vhttp_linklist_unlink(&ref->_lru);

    /* and close */
    vhttp_filecache_close_file(ref);
}

vhttp_filecache_t *vhttp_filecache_create(size_t capacity)
{
    vhttp_filecache_t *cache = vhttp_mem_alloc(sizeof(*cache));

    cache->hash = kh_init(opencache_set);
    vhttp_linklist_init_anchor(&cache->lru);
    cache->capacity = capacity;

    return cache;
}

void vhttp_filecache_destroy(vhttp_filecache_t *cache)
{
    vhttp_filecache_clear(cache);
    assert(kh_size(cache->hash) == 0);
    assert(vhttp_linklist_is_empty(&cache->lru));
    kh_destroy(opencache_set, cache->hash);
    free(cache);
}

void vhttp_filecache_clear(vhttp_filecache_t *cache)
{
    khiter_t iter;
    for (iter = kh_begin(cache->hash); iter != kh_end(cache->hash); ++iter) {
        if (!kh_exist(cache->hash, iter))
            continue;
        release_from_cache(cache, iter);
    }
    assert(kh_size(cache->hash) == 0);
}

vhttp_filecache_ref_t *vhttp_filecache_open_file(vhttp_filecache_t *cache, const char *path, int oflag)
{
    khiter_t iter = kh_get(opencache_set, cache->hash, path);
    vhttp_filecache_ref_t *ref;
    int dummy;

    /* lookup cache, and return the one if found */
    if (iter != kh_end(cache->hash)) {
        ref = vhttp_STRUCT_FROM_MEMBER(vhttp_filecache_ref_t, _path, kh_key(cache->hash, iter));
        ++ref->_refcnt;
        goto Exit;
    }

    /* create a new cache entry */
    ref = vhttp_mem_alloc(offsetof(vhttp_filecache_ref_t, _path) + strlen(path) + 1);
    ref->_refcnt = 1;
    ref->_lru = (vhttp_linklist_t){NULL};
    strcpy(ref->_path, path);

    /* if cache is used, then... */
    if (cache->capacity != 0) {
        /* purge one entry from LRU if cache is full */
        if (kh_size(cache->hash) == cache->capacity) {
            vhttp_filecache_ref_t *purge_ref = vhttp_STRUCT_FROM_MEMBER(vhttp_filecache_ref_t, _lru, cache->lru.prev);
            khiter_t purge_iter = kh_get(opencache_set, cache->hash, purge_ref->_path);
            assert(purge_iter != kh_end(cache->hash));
            release_from_cache(cache, purge_iter);
        }
        /* assign the new entry */
        ++ref->_refcnt;
        kh_put(opencache_set, cache->hash, ref->_path, &dummy);
        vhttp_linklist_insert(cache->lru.next, &ref->_lru);
    }

    /* open the file, or memoize the error */
    if ((ref->fd = open(path, oflag)) != -1 && fstat(ref->fd, &ref->st) == 0) {
        ref->_last_modified.str[0] = '\0';
        ref->_etag.len = 0;
    } else {
        ref->open_err = errno;
        if (ref->fd != -1) {
            close(ref->fd);
            ref->fd = -1;
        }
    }

Exit:
    /* if the cache entry retains an error, return it instead of the reference */
    if (ref->fd == -1) {
        errno = ref->open_err;
        vhttp_filecache_close_file(ref);
        ref = NULL;
    }
    return ref;
}

void vhttp_filecache_close_file(vhttp_filecache_ref_t *ref)
{
    if (--ref->_refcnt != 0)
        return;
    assert(!vhttp_linklist_is_linked(&ref->_lru));
    if (ref->fd != -1) {
        close(ref->fd);
        ref->fd = -1;
    }
    free(ref);
}

struct tm *vhttp_filecache_get_last_modified(vhttp_filecache_ref_t *ref, char *outbuf)
{
    assert(ref->fd != -1);
    if (ref->_last_modified.str[0] == '\0') {
        gmtime_r(&ref->st.st_mtime, &ref->_last_modified.gm);
        vhttp_time2str_rfc1123(ref->_last_modified.str, &ref->_last_modified.gm);
    }
    if (outbuf != NULL)
        memcpy(outbuf, ref->_last_modified.str, vhttp_TIMESTR_RFC1123_LEN + 1);
    return &ref->_last_modified.gm;
}

size_t vhttp_filecache_get_etag(vhttp_filecache_ref_t *ref, char *outbuf)
{
    assert(ref->fd != -1);
    if (ref->_etag.len == 0)
        ref->_etag.len = sprintf(ref->_etag.buf, "\"%08x-%zx\"", (unsigned)ref->st.st_mtime, (size_t)ref->st.st_size);
    memcpy(outbuf, ref->_etag.buf, ref->_etag.len + 1);
    return ref->_etag.len;
}

int vhttp_filecache_compare_etag_strong(const char *tag1, size_t tag1_len, const char *tag2, size_t tag2_len)
{
    size_t i;

    /* first check if tag1 a valid strong etag, then just strictly compare tag1 with tag2 */
    if (tag1_len < sizeof("\"\"")) /* strong etag should be at least one character quoted */
        return 0;
    if (tag1[0] != '"' || tag1[tag1_len - 1] != '"') /* not a valid etag */
        return 0;
    for (i = 1; i < tag1_len - 1; i++) {
        if (tag1[i] < 0x21 || tag1[i] == '"') /* VCHAR except double quotes, plus obs-text */
            return 0;
    }
    return vhttp_memis(tag1, tag1_len, tag2, tag2_len);
}
