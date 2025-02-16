/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <stdlib.h>
#include "vhttp.h"
#include "brotli/encode.h"

struct st_brotli_context_t {
    vhttp_compress_context_t super;
    BrotliEncoderState *state;
    vhttp_VECTOR(vhttp_sendvec_t) bufs;
    size_t buf_capacity;
};

static void expand_buf(struct st_brotli_context_t *self)
{
    vhttp_vector_reserve(NULL, &self->bufs, self->bufs.size + 1);
    vhttp_sendvec_init_raw(self->bufs.entries + self->bufs.size++, vhttp_mem_alloc(self->buf_capacity), 0);
}

static void shrink_buf(struct st_brotli_context_t *self, size_t new_size)
{
    while (new_size < self->bufs.size)
        free(self->bufs.entries[--self->bufs.size].raw);
}

static void compress_core(struct st_brotli_context_t *self, BrotliEncoderOperation op, const uint8_t **src, size_t *srclen)
{
    size_t bufindex = self->bufs.size - 1;

    if (self->bufs.entries[bufindex].len == self->buf_capacity) {
        expand_buf(self);
        ++bufindex;
    }
    uint8_t *dst = (uint8_t *)self->bufs.entries[bufindex].raw + self->bufs.entries[bufindex].len;
    size_t dstlen = self->buf_capacity - self->bufs.entries[bufindex].len;

    if (!BrotliEncoderCompressStream(self->state, op, srclen, src, &dstlen, &dst, NULL))
        vhttp_fatal("BrotliEncoderCompressStream");

    self->bufs.entries[bufindex].len = self->buf_capacity - dstlen;
}

static vhttp_send_state_t compress_(vhttp_compress_context_t *_self, vhttp_sendvec_t *inbufs, size_t inbufcnt, vhttp_send_state_t state,
                                  vhttp_sendvec_t **outbufs, size_t *outbufcnt)
{
    struct st_brotli_context_t *self = (void *)_self;
    BrotliEncoderOperation final_op = vhttp_send_state_is_in_progress(state) ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_FINISH;
    const uint8_t *src;
    size_t i, srclen;

    shrink_buf(self, 1);
    self->bufs.entries[0].len = 0;

    /* encode chunks and flush */
    if (inbufcnt != 0) {
        for (i = 0; i < inbufcnt; ++i) {
            assert(inbufs[i].callbacks->read_ == vhttp_sendvec_read_raw);
            src = (void *)inbufs[i].raw;
            srclen = inbufs[i].len;
            BrotliEncoderOperation op = i + 1 == inbufcnt ? final_op : BROTLI_OPERATION_PROCESS;
            while (srclen != 0)
                compress_core(self, op, &src, &srclen);
        }
    } else {
        src = NULL;
        srclen = 0;
        compress_core(self, final_op, &src, &srclen);
    }

    /* emit pending output, if any */
    while (BrotliEncoderHasMoreOutput(self->state)) {
        src = NULL;
        srclen = 0;
        compress_core(self, final_op, &src, &srclen);
    }

    *outbufs = self->bufs.entries;
    *outbufcnt = self->bufs.size - (self->bufs.entries[self->bufs.size - 1].len == 0);

    return state;
}

static void on_dispose(void *_self)
{
    struct st_brotli_context_t *self = _self;

    BrotliEncoderDestroyInstance(self->state);
    shrink_buf(self, 0);
    free(self->bufs.entries);
    free(self->super.push_buf);
}

vhttp_compress_context_t *vhttp_compress_brotli_open(vhttp_mem_pool_t *pool, int quality, size_t estimated_content_length,
                                                 size_t preferred_chunk_size)
{
    struct st_brotli_context_t *self = vhttp_mem_alloc_shared(pool, sizeof(struct st_brotli_context_t), on_dispose);

    self->super.name = vhttp_iovec_init(vhttp_STRLIT("br"));
    self->super.do_transform = compress_;
    self->super.push_buf = NULL;
    self->state = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    memset(&self->bufs, 0, sizeof(self->bufs));
    self->buf_capacity = preferred_chunk_size;
    if (self->buf_capacity > estimated_content_length)
        self->buf_capacity = estimated_content_length;
    if (self->buf_capacity > 65536)
        self->buf_capacity = 65536;
    if (self->buf_capacity < 1024)
        self->buf_capacity = 1024;
    expand_buf(self);

    BrotliEncoderSetParameter(self->state, BROTLI_PARAM_QUALITY, quality);
    if (estimated_content_length < (1 << BROTLI_DEFAULT_WINDOW) / 2) {
        unsigned bits =
            estimated_content_length > 1 ? sizeof(unsigned long long) * 8 - __builtin_clzll(estimated_content_length - 1) : 1;
        if (bits < 5) {
            bits = 5;
        }
        BrotliEncoderSetParameter(self->state, BROTLI_PARAM_LGWIN, bits);
    }

    return &self->super;
}
