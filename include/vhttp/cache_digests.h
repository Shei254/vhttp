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
#ifndef vhttp__cache_digests_h
#define vhttp__cache_digests_h

#include <stddef.h>
#include <stdlib.h>
#include "vhttp/memory.h"

typedef enum en_vhttp_cache_digests_state_t {
    vhttp_CACHE_DIGESTS_STATE_UNKNOWN,
    vhttp_CACHE_DIGESTS_STATE_NOT_CACHED,
    vhttp_CACHE_DIGESTS_STATE_FRESH,
    vhttp_CACHE_DIGESTS_STATE_STALE
} vhttp_cache_digests_state_t;

typedef struct st_vhttp_cache_digests_frame_t vhttp_cache_digests_frame_t;

typedef vhttp_VECTOR(vhttp_cache_digests_frame_t) vhttp_cache_digests_frame_vector_t;

typedef struct st_vhttp_cache_digests_t {
    struct {
        vhttp_cache_digests_frame_vector_t url_only;
        vhttp_cache_digests_frame_vector_t url_and_etag;
        int complete;
    } fresh;
} vhttp_cache_digests_t;

/**
 * destroys the object
 */
void vhttp_cache_digests_destroy(vhttp_cache_digests_t *digests);
/**
 * loads a header (*digests may be NULL)
 */
void vhttp_cache_digests_load_header(vhttp_cache_digests_t **digests, const char *value, size_t len);
/**
 * lookup for a match with URL only
 */
vhttp_cache_digests_state_t vhttp_cache_digests_lookup_by_url(vhttp_cache_digests_t *digests, const char *url, size_t url_len);
/**
 * lookup for a match with URL and etag
 */
vhttp_cache_digests_state_t vhttp_cache_digests_lookup_by_url_and_etag(vhttp_cache_digests_t *digests, const char *url, size_t url_len,
                                                                   const char *etag, size_t etag_len);

#endif
