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
#ifndef vhttp__filecache_h
#define vhttp__filecache_h

#include <stddef.h>
#include <sys/stat.h>
#include <time.h>
#include "vhttp/linklist.h"
#include "vhttp/memory.h"
#include "vhttp/time_.h"

#define vhttp_FILECACHE_ETAG_MAXLEN (sizeof("\"deadbeef-deadbeefdeadbeef\"") - 1)

typedef struct st_vhttp_filecache_ref_t {
    int fd;
    size_t _refcnt;
    vhttp_linklist_t _lru;
    union {
        struct {
            /* used if fd != -1 */
            struct stat st;
            struct {
                struct tm gm;
                char str[vhttp_TIMESTR_RFC1123_LEN + 1];
            } _last_modified;
            struct {
                char buf[vhttp_FILECACHE_ETAG_MAXLEN + 1];
                size_t len;
            } _etag;
        };
        /* used if fd != -1 */
        int open_err;
    };
    char _path[1];
} vhttp_filecache_ref_t;

typedef struct st_vhttp_filecache_t vhttp_filecache_t;

vhttp_filecache_t *vhttp_filecache_create(size_t capacity);
void vhttp_filecache_destroy(vhttp_filecache_t *cache);
void vhttp_filecache_clear(vhttp_filecache_t *cache);

vhttp_filecache_ref_t *vhttp_filecache_open_file(vhttp_filecache_t *cache, const char *path, int oflag);
void vhttp_filecache_close_file(vhttp_filecache_ref_t *ref);
struct tm *vhttp_filecache_get_last_modified(vhttp_filecache_ref_t *ref, char *outbuf);
size_t vhttp_filecache_get_etag(vhttp_filecache_ref_t *ref, char *outbuf);
int vhttp_filecache_compare_etag_strong(const char *tag1, size_t tag1_len, const char *tag2, size_t tag2_len);

#endif
