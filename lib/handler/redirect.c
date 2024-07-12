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
#include <stdlib.h>
#include "vhttp.h"

#define MODULE_NAME "lib/handler/redirect.c"

typedef vhttp_VECTOR(char *) char_vec;

struct st_vhttp_redirect_handler_t {
    vhttp_handler_t super;
    int internal;
    int status;
    vhttp_iovec_vector_t prefix_list;
};

static void on_dispose(vhttp_handler_t *_self)
{
    vhttp_redirect_handler_t *self = (void *)_self;
    size_t i;
    for (i = 0; i != self->prefix_list.size; ++i) {
        free(self->prefix_list.entries[i].base);
    }
    free(self->prefix_list.entries);
}

static void redirect_internally(vhttp_redirect_handler_t *self, vhttp_req_t *req, vhttp_iovec_t dest)
{
    vhttp_iovec_t method;
    vhttp_url_t resolved;
    if (vhttp_req_resolve_internal_redirect_url(req, dest, &resolved) != 0) {
        vhttp_req_log_error(req, MODULE_NAME, "failed to resolve internal redirect url for dest:%.*s", (int)dest.len, dest.base);
        vhttp_send_error_503(req, "Internal Server Error", "internal server error", 0);
        return;
    }

    /* determine the method */
    switch (self->status) {
    case 307:
    case 308:
        method = req->method;
        break;
    default:
        method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        req->entity = (vhttp_iovec_t){NULL};
        break;
    }

    vhttp_reprocess_request_deferred(req, method, resolved.scheme, resolved.authority, resolved.path, NULL, 1);
}

static int on_req(vhttp_handler_t *_self, vhttp_req_t *req)
{
    vhttp_redirect_handler_t *self = (void *)_self;

    vhttp_iovec_t delimiter =
        req->authority_wildcard_match.base == NULL ? vhttp_iovec_init(vhttp_STRLIT("*")) : req->authority_wildcard_match;
    vhttp_iovec_t prefix = vhttp_join_list(&req->pool, self->prefix_list.entries, self->prefix_list.size, delimiter);
    vhttp_iovec_t dest = vhttp_build_destination(req, prefix.base, prefix.len, 1);

    /* redirect */
    if (self->internal) {
        redirect_internally(self, req, dest);
    } else {
        vhttp_send_redirect(req, self->status, "Redirected", dest.base, dest.len);
    }

    return 0;
}

vhttp_redirect_handler_t *vhttp_redirect_register(vhttp_pathconf_t *pathconf, int internal, int status, const char *prefix)
{
    vhttp_redirect_handler_t *self = (void *)vhttp_create_handler(pathconf, sizeof(*self));
    self->super.dispose = on_dispose;
    self->super.on_req = on_req;
    self->internal = internal;
    self->status = status;
    vhttp_split(NULL, &self->prefix_list, vhttp_iovec_init(prefix, strlen(prefix)), '*');

    return self;
}
