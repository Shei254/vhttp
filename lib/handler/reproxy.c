/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Daisuke Maki
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

static void on_send(vhttp_ostream_t *self, vhttp_req_t *req, vhttp_sendvec_t *inbufs, size_t inbufcnt, vhttp_send_state_t state)
{
    /* nothing to do */
}

static void on_setup_ostream(vhttp_filter_t *self, vhttp_req_t *req, vhttp_ostream_t **slot)
{
    vhttp_iovec_t dest, method;
    ssize_t xru_index;

    /* obtain x-reproxy-url header, or skip to next ostream */
    if ((xru_index = vhttp_find_header(&req->res.headers, vhttp_TOKEN_X_REPROXY_URL, -1)) == -1) {
        vhttp_setup_next_ostream(req, slot);
        return;
    }
    dest = req->res.headers.entries[xru_index].value;
    vhttp_delete_header(&req->res.headers, xru_index);

    /* setup params */
    switch (req->res.status) {
    case 307:
    case 308:
        method = req->method;
        break;
    default:
        method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        req->entity = (vhttp_iovec_t){NULL};
        break;
    }

    /* request internal redirect (is deferred) */
    vhttp_send_redirect_internal(req, method, dest.base, dest.len, 0);

    /* setup filter (that swallows the response until the timeout gets fired) */
    vhttp_ostream_t *ostream = vhttp_add_ostream(req, vhttp_ALIGNOF(*ostream), sizeof(*ostream), slot);
    ostream->do_send = on_send;
}

void vhttp_reproxy_register(vhttp_pathconf_t *pathconf)
{
    vhttp_filter_t *self = vhttp_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
