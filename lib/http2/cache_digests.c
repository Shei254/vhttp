/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include <limits.h>
#include <stdlib.h>
#ifndef vhttp_NO_OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED /* cache-digests is legacy and we do not want to pay the cost of switchng away from SHA256_* */
#endif
#include <openssl/sha.h>
#include "golombset.h"
#include "vhttp/string_.h"
#include "vhttp/cache_digests.h"

struct st_vhttp_cache_digests_frame_t {
    vhttp_VECTOR(uint64_t) keys;
    unsigned capacity_bits;
};

static void dispose_frame_vector(vhttp_cache_digests_frame_vector_t *v)
{
    size_t i;
    for (i = 0; i != v->size; ++i)
        free(v->entries[i].keys.entries);
    free(v->entries);
}

static void dispose_digests(vhttp_cache_digests_t *digests)
{
    dispose_frame_vector(&digests->fresh.url_only);
    dispose_frame_vector(&digests->fresh.url_and_etag);
}

void vhttp_cache_digests_destroy(vhttp_cache_digests_t *digests)
{
    dispose_digests(digests);
    free(digests);
}

static void load_digest(vhttp_cache_digests_t **digests, const char *gcs_base64, size_t gcs_base64_len, int with_validators,
                        int complete)
{
    vhttp_cache_digests_frame_t frame = {{NULL}};
    vhttp_iovec_t gcs_bin;
    struct st_golombset_decode_t ctx = {NULL};
    uint64_t nbits, pbits;

    /* decode base64 */
    if ((gcs_bin = vhttp_decode_base64url(NULL, gcs_base64, gcs_base64_len)).base == NULL)
        goto Exit;

    /* prepare GCS context */
    ctx.src = (void *)(gcs_bin.base - 1);
    ctx.src_max = (void *)(gcs_bin.base + gcs_bin.len);
    ctx.src_shift = 0;

    /* decode nbits and pbits */
    if (golombset_decode_bits(&ctx, 5, &nbits) != 0 || golombset_decode_bits(&ctx, 5, &pbits) != 0)
        goto Exit;
    frame.capacity_bits = (unsigned)(nbits + pbits);

    /* decode the values */
    uint64_t value = UINT64_MAX, decoded;
    while (golombset_decode_value(&ctx, (unsigned)pbits, &decoded) == 0) {
        value += decoded + 1;
        if (value >= (uint64_t)1 << frame.capacity_bits)
            goto Exit;
        vhttp_vector_reserve(NULL, &frame.keys, frame.keys.size + 1);
        frame.keys.entries[frame.keys.size++] = value;
    }

    /* store the result */
    if (*digests == NULL) {
        *digests = vhttp_mem_alloc(sizeof(**digests));
        **digests = (vhttp_cache_digests_t){{{NULL}}};
    }
    vhttp_cache_digests_frame_vector_t *target = with_validators ? &(*digests)->fresh.url_and_etag : &(*digests)->fresh.url_only;
    vhttp_vector_reserve(NULL, target, target->size + 1);
    target->entries[target->size++] = frame;
    frame = (vhttp_cache_digests_frame_t){{NULL}};
    (*digests)->fresh.complete = complete;

Exit:
    free(frame.keys.entries);
    free(gcs_bin.base);
}

void vhttp_cache_digests_load_header(vhttp_cache_digests_t **digests, const char *value, size_t len)
{
    vhttp_iovec_t iter = vhttp_iovec_init(value, len);
    const char *token;
    size_t token_len;

    do {
        const char *gcs_base64;
        size_t gcs_base64_len;
        int reset = 0, validators = 0, complete = 0, skip = 0;
        vhttp_iovec_t token_value;

        if ((gcs_base64 = vhttp_next_token(&iter, ';', ',', &gcs_base64_len, NULL)) == NULL)
            return;
        while ((token = vhttp_next_token(&iter, ';', ',', &token_len, &token_value)) != NULL &&
               !vhttp_memis(token, token_len, vhttp_STRLIT(","))) {
            if (vhttp_lcstris(token, token_len, vhttp_STRLIT("reset"))) {
                reset = 1;
            } else if (vhttp_lcstris(token, token_len, vhttp_STRLIT("validators"))) {
                validators = 1;
            } else if (vhttp_lcstris(token, token_len, vhttp_STRLIT("complete"))) {
                complete = 1;
            } else {
                skip = 1;
            }
        }

        if (reset && *digests != NULL) {
            vhttp_cache_digests_destroy(*digests);
            *digests = NULL;
        }

        if (skip) {
            /* not supported for the time being */
        } else {
            load_digest(digests, gcs_base64, gcs_base64_len, validators, complete);
        }
    } while (token != NULL);
}

static uint64_t calc_hash(const char *url, size_t url_len, const char *etag, size_t etag_len)
{
    SHA256_CTX ctx;
    union {
        unsigned char bytes[SHA256_DIGEST_LENGTH];
        uint64_t u64;
    } md;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, url, url_len);
    SHA256_Update(&ctx, etag, etag_len);
    SHA256_Final(md.bytes, &ctx);

    if (*(uint16_t *)"\xde\xad" == 0xdead)
        return md.u64;
    else
        return __builtin_bswap64(md.u64);
}

static int cmp_key(const void *_x, const void *_y)
{
    uint64_t x = *(uint64_t *)_x, y = *(uint64_t *)_y;

    if (x < y) {
        return -1;
    } else if (x > y) {
        return 1;
    } else {
        return 0;
    }
}

static int lookup(vhttp_cache_digests_frame_vector_t *vector, const char *url, size_t url_len, const char *etag, size_t etag_len,
                  int is_fresh, int is_complete)
{
    if (vector->size != 0) {
        uint64_t hash = calc_hash(url, url_len, etag, etag_len);
        size_t i = 0;
        do {
            vhttp_cache_digests_frame_t *frame = vector->entries + i;
            uint64_t key = hash >> (64 - frame->capacity_bits);
            if (frame->keys.entries != NULL &&
                bsearch(&key, frame->keys.entries, frame->keys.size, sizeof(frame->keys.entries[0]), cmp_key) != NULL)
                return is_fresh ? vhttp_CACHE_DIGESTS_STATE_FRESH : vhttp_CACHE_DIGESTS_STATE_STALE;
        } while (++i != vector->size);
    }

    return is_complete ? vhttp_CACHE_DIGESTS_STATE_NOT_CACHED : vhttp_CACHE_DIGESTS_STATE_UNKNOWN;
}

vhttp_cache_digests_state_t vhttp_cache_digests_lookup_by_url(vhttp_cache_digests_t *digests, const char *url, size_t url_len)
{
    return lookup(&digests->fresh.url_only, url, url_len, "", 0, 1, digests->fresh.complete);
}

vhttp_cache_digests_state_t vhttp_cache_digests_lookup_by_url_and_etag(vhttp_cache_digests_t *digests, const char *url, size_t url_len,
                                                                   const char *etag, size_t etag_len)
{
    return lookup(&digests->fresh.url_and_etag, url, url_len, etag, etag_len, 1, digests->fresh.complete);
}
