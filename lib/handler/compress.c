/*
 * Copyright (c) 2015,2016 Justin Zhu, DeNA Co., Ltd., Kazuho Oku
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

#ifndef BUF_SIZE
#define BUF_SIZE 8192
#endif

struct st_compress_filter_t {
    vhttp_filter_t super;
    vhttp_compress_args_t args;
};

struct st_compress_encoder_t {
    vhttp_ostream_t super;
    vhttp_compress_context_t *compressor;
};

static void do_send(vhttp_ostream_t *_self, vhttp_req_t *req, vhttp_sendvec_t *inbufs, size_t inbufcnt, vhttp_send_state_t state)
{
    struct st_compress_encoder_t *self = (void *)_self;
    vhttp_sendvec_t *outbufs;
    size_t outbufcnt;

    if (inbufcnt == 0 && vhttp_send_state_is_in_progress(state)) {
        vhttp_ostream_send_next(&self->super, req, inbufs, inbufcnt, state);
        return;
    }

    state = vhttp_compress_transform(self->compressor, req, inbufs, inbufcnt, state, &outbufs, &outbufcnt);
    vhttp_ostream_send_next(&self->super, req, outbufs, outbufcnt, state);
}

static void on_setup_ostream(vhttp_filter_t *_self, vhttp_req_t *req, vhttp_ostream_t **slot)
{
    struct st_compress_filter_t *self = (void *)_self;
    struct st_compress_encoder_t *encoder;
    int compressible_types;
    int compressible_types_mask = vhttp_COMPRESSIBLE_BROTLI | vhttp_COMPRESSIBLE_GZIP | vhttp_COMPRESSIBLE_ZSTD;
    vhttp_compress_context_t *compressor;
    ssize_t i;

    if (req->version < 0x101)
        goto Next;
    if (req->res.status != 200)
        goto Next;
    if (vhttp_memis(req->input.method.base, req->input.method.len, vhttp_STRLIT("HEAD")))
        goto Next;

    switch (req->compress_hint) {
    case vhttp_COMPRESS_HINT_DISABLE:
        /* compression was explicitly disabled, skip */
        goto Next;
    case vhttp_COMPRESS_HINT_ENABLE:
        /* compression was explicitly enabled */
        break;
    case vhttp_COMPRESS_HINT_ENABLE_BR:
        compressible_types_mask = vhttp_COMPRESSIBLE_BROTLI;
        break;
    case vhttp_COMPRESS_HINT_ENABLE_GZIP:
        compressible_types_mask = vhttp_COMPRESSIBLE_GZIP;
        break;
    case vhttp_COMPRESS_HINT_ENABLE_ZSTD:
        compressible_types_mask = vhttp_COMPRESSIBLE_ZSTD;
        break;
    case vhttp_COMPRESS_HINT_AUTO:
    default:
        /* no hint from the producer, decide whether to compress based
           on the configuration */
        if (req->res.mime_attr == NULL)
            vhttp_req_fill_mime_attributes(req);
        if (!req->res.mime_attr->is_compressible)
            goto Next;
        if (req->res.content_length < self->args.min_size)
            goto Next;
    }

    /* skip if failed to gather the list of compressible types */
    compressible_types = vhttp_get_compressible_types(&req->headers) & compressible_types_mask;
    if (compressible_types == 0)
        goto Next;

    /* skip if content-encoding header is being set (as well as obtain the location of accept-ranges moreover identify index of etag
     * to modified weaken) */
    size_t content_encoding_header_index = -1, accept_ranges_header_index = -1, etag_header_index = -1;
    for (i = 0; i != req->res.headers.size; ++i) {
        if (req->res.headers.entries[i].name == &vhttp_TOKEN_CONTENT_ENCODING->buf)
            content_encoding_header_index = i;
        else if (req->res.headers.entries[i].name == &vhttp_TOKEN_ACCEPT_RANGES->buf)
            accept_ranges_header_index = i;
        else if (req->res.headers.entries[i].name == &vhttp_TOKEN_ETAG->buf)
            etag_header_index = i;
        else
            continue;
    }
    if (content_encoding_header_index != -1)
        goto Next;

/* open the compressor (TODO add support for zstd) */
#if vhttp_USE_BROTLI
    if (self->args.brotli.quality != -1 && (compressible_types & vhttp_COMPRESSIBLE_BROTLI) != 0) {
        compressor =
            vhttp_compress_brotli_open(&req->pool, self->args.brotli.quality, req->res.content_length, req->preferred_chunk_size);
    } else
#endif
        if (self->args.gzip.quality != -1 && (compressible_types & vhttp_COMPRESSIBLE_GZIP) != 0) {
        compressor = vhttp_compress_gzip_open(&req->pool, self->args.gzip.quality);
    } else {
        /* let proxies know that we looked at accept-encoding when deciding not to compress */
        vhttp_set_header_token(&req->pool, &req->res.headers, vhttp_TOKEN_VARY, vhttp_STRLIT("accept-encoding"));
        goto Next;
    }

    /* adjust the response headers */
    req->res.content_length = SIZE_MAX;
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CONTENT_ENCODING, NULL, compressor->name.base, compressor->name.len);
    vhttp_set_header_token(&req->pool, &req->res.headers, vhttp_TOKEN_VARY, vhttp_STRLIT("accept-encoding"));
    if (etag_header_index != -1) {
        if (!(req->res.headers.entries[etag_header_index].value.len >= 2 &&
              vhttp_memis(req->res.headers.entries[etag_header_index].value.base, 2, vhttp_STRLIT("W/")))) {
            req->res.headers.entries[etag_header_index].value =
                vhttp_concat(&req->pool, vhttp_iovec_init(vhttp_STRLIT("W/")), req->res.headers.entries[etag_header_index].value);
        }
    }
    if (accept_ranges_header_index != -1) {
        req->res.headers.entries[accept_ranges_header_index].value = vhttp_iovec_init(vhttp_STRLIT("none"));
    } else {
        vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_ACCEPT_RANGES, NULL, vhttp_STRLIT("none"));
    }

    /* setup filter */
    encoder = (void *)vhttp_add_ostream(req, vhttp_ALIGNOF(*encoder), sizeof(*encoder), slot);
    encoder->super.do_send = do_send;
    slot = &encoder->super.next;
    encoder->compressor = compressor;

    /* adjust preferred chunk size (compress by 8192 bytes) */
    if (req->preferred_chunk_size > BUF_SIZE)
        req->preferred_chunk_size = BUF_SIZE;

Next:
    vhttp_setup_next_ostream(req, slot);
}

void vhttp_compress_register(vhttp_pathconf_t *pathconf, vhttp_compress_args_t *args)
{
    struct st_compress_filter_t *self = (void *)vhttp_create_filter(pathconf, sizeof(*self));
    self->super.on_setup_ostream = on_setup_ostream;
    self->args = *args;
}

vhttp_send_state_t vhttp_compress_transform(vhttp_compress_context_t *self, vhttp_req_t *req, vhttp_sendvec_t *inbufs, size_t inbufcnt,
                                        vhttp_send_state_t state, vhttp_sendvec_t **outbufs, size_t *outbufcnt)
{
    vhttp_sendvec_t flattened;

    if (inbufcnt != 0 && inbufs->callbacks->read_ != &vhttp_sendvec_read_raw) {
        assert(inbufcnt == 1);
        size_t buflen = inbufs->len;
        assert(buflen <= vhttp_PULL_SENDVEC_MAX_SIZE);
        if (self->push_buf == NULL)
            self->push_buf = vhttp_mem_alloc(vhttp_send_state_is_in_progress(state) ? vhttp_PULL_SENDVEC_MAX_SIZE : buflen);
        if (!(*inbufs->callbacks->read_)(inbufs, self->push_buf, buflen)) {
            *outbufs = NULL;
            *outbufcnt = 0;
            return vhttp_SEND_STATE_ERROR;
        }
        vhttp_sendvec_init_raw(&flattened, self->push_buf, buflen);
        inbufs = &flattened;
    }

    return self->do_transform(self, inbufs, inbufcnt, state, outbufs, outbufcnt);
}
