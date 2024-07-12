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
#include "vhttp.h"

/* used to rewrite status code to the original code */
struct st_errordoc_prefilter_t {
    vhttp_req_prefilter_t super;
    vhttp_headers_t req_headers;
    int status;
    const char *reason;
    vhttp_headers_t res_headers;
};

/* used to capture an error response */
struct st_errordoc_filter_t {
    vhttp_filter_t super;
    vhttp_VECTOR(vhttp_errordoc_t) errordocs;
};

static void add_header(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, const vhttp_header_t *header)
{
    vhttp_vector_reserve(pool, headers, headers->size + 1);
    headers->entries[headers->size++] = *header;
}

static void on_prefilter_setup_stream(vhttp_req_prefilter_t *_self, vhttp_req_t *req, vhttp_ostream_t **slot)
{
    struct st_errordoc_prefilter_t *self = (void *)_self;
    vhttp_headers_t headers_merged = {NULL};
    size_t i;

    /* restore request headers (for logging) and response status */
    req->headers = self->req_headers;
    req->res.status = self->status;
    req->res.reason = self->reason;

    /* generate response headers (by merging the preserved and given) */
    for (i = 0; i != self->res_headers.size; ++i)
        add_header(&req->pool, &headers_merged, self->res_headers.entries + i);
    for (i = 0; i != req->res.headers.size; ++i) {
        const vhttp_header_t *header = req->res.headers.entries + i;
        if (header->name == &vhttp_TOKEN_CONTENT_TYPE->buf || header->name == &vhttp_TOKEN_CONTENT_LANGUAGE->buf ||
            header->name == &vhttp_TOKEN_SET_COOKIE->buf)
            add_header(&req->pool, &headers_merged, header);
    }
    req->res.headers = headers_merged;

    vhttp_setup_next_prefilter(&self->super, req, slot);
}

static void on_ostream_send(vhttp_ostream_t *self, vhttp_req_t *req, vhttp_sendvec_t *inbufs, size_t inbufcnt, vhttp_send_state_t state)
{
    /* nothing to do */
}

static int prefilter_is_registered(vhttp_req_t *req)
{
    vhttp_req_prefilter_t *prefilter;
    for (prefilter = req->prefilters; prefilter != NULL; prefilter = prefilter->next)
        if (prefilter->on_setup_ostream == on_prefilter_setup_stream)
            return 1;
    return 0;
}

static void on_filter_setup_ostream(vhttp_filter_t *_self, vhttp_req_t *req, vhttp_ostream_t **slot)
{
    struct st_errordoc_filter_t *self = (void *)_self;
    vhttp_errordoc_t *errordoc;
    struct st_errordoc_prefilter_t *prefilter;
    vhttp_iovec_t method;
    vhttp_ostream_t *ostream;
    size_t i;

    if (req->res.status >= 400 && !prefilter_is_registered(req)) {
        size_t i;
        for (i = 0; i != self->errordocs.size; ++i) {
            errordoc = self->errordocs.entries + i;
            if (errordoc->status == req->res.status)
                goto Found;
        }
    }

    /* bypass to the next filter */
    vhttp_setup_next_ostream(req, slot);
    return;

Found:
    /* register prefilter that rewrites the status code after the internal redirect is processed */
    prefilter = (void *)vhttp_add_prefilter(req, vhttp_ALIGNOF(*prefilter), sizeof(*prefilter));
    prefilter->super.on_setup_ostream = on_prefilter_setup_stream;
    prefilter->req_headers = req->headers;
    prefilter->status = req->res.status;
    prefilter->reason = req->res.reason;
    prefilter->res_headers = (vhttp_headers_t){NULL};
    for (i = 0; i != req->res.headers.size; ++i) {
        const vhttp_header_t *header = req->res.headers.entries + i;
        if (!(header->name == &vhttp_TOKEN_CONTENT_TYPE->buf || header->name == &vhttp_TOKEN_CONTENT_LANGUAGE->buf))
            add_header(&req->pool, &prefilter->res_headers, header);
    }
    /* redirect internally to the error document */
    method = req->method;
    if (vhttp_memis(method.base, method.len, vhttp_STRLIT("POST")))
        method = vhttp_iovec_init(vhttp_STRLIT("GET"));
    req->headers = (vhttp_headers_t){NULL};
    req->res.headers = (vhttp_headers_t){NULL};
    vhttp_send_redirect_internal(req, method, errordoc->url.base, errordoc->url.len, 0);
    /* create fake ostream that swallows the contents emitted by the generator */
    ostream = vhttp_add_ostream(req, vhttp_ALIGNOF(*ostream), sizeof(*ostream), slot);
    ostream->do_send = on_ostream_send;
}

void vhttp_errordoc_register(vhttp_pathconf_t *pathconf, vhttp_errordoc_t *errdocs, size_t cnt)
{
    struct st_errordoc_filter_t *self = (void *)vhttp_create_filter(pathconf, sizeof(*self));
    size_t i;

    self->super.on_setup_ostream = on_filter_setup_ostream;
    vhttp_vector_reserve(NULL, &self->errordocs, cnt);
    self->errordocs.size = cnt;
    for (i = 0; i != cnt; ++i) {
        const vhttp_errordoc_t *src = errdocs + i;
        vhttp_errordoc_t *dst = self->errordocs.entries + i;
        dst->status = src->status;
        dst->url = vhttp_strdup(NULL, src->url.base, src->url.len);
    }
}
