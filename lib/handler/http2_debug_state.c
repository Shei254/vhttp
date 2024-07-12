/*
 * Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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
#include <inttypes.h>
#include "vhttp.h"

struct st_vhttp_http2_debug_state_handler_t {
    vhttp_handler_t super;
    int hpack_enabled;
};

static int on_req(vhttp_handler_t *_self, vhttp_req_t *req)
{
    struct st_vhttp_http2_debug_state_handler_t *self = (void *)_self;

    static vhttp_generator_t generator = {NULL, NULL};

    if (req->conn->callbacks->get_debug_state == NULL) {
        return -1;
    }

    vhttp_http2_debug_state_t *debug_state = req->conn->callbacks->get_debug_state(req, self->hpack_enabled);

    // stringify these variables to embed in Debug Header
    vhttp_iovec_t conn_flow_in, conn_flow_out;
    conn_flow_in.base = vhttp_mem_alloc_pool(&req->pool, char, sizeof(vhttp_INT64_LONGEST_STR));
    conn_flow_in.len = sprintf(conn_flow_in.base, "%zd", debug_state->conn_flow_in);
    conn_flow_out.base = vhttp_mem_alloc_pool(&req->pool, char, sizeof(vhttp_INT64_LONGEST_STR));
    conn_flow_out.len = sprintf(conn_flow_out.base, "%zd", debug_state->conn_flow_out);

    req->res.status = 200;
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CONTENT_TYPE, NULL, vhttp_STRLIT("application/json; charset=utf-8"));
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CACHE_CONTROL, NULL, vhttp_STRLIT("no-cache, no-store"));
    vhttp_add_header_by_str(&req->pool, &req->res.headers, vhttp_STRLIT("conn-flow-in"), 0, NULL, conn_flow_in.base, conn_flow_in.len);
    vhttp_add_header_by_str(&req->pool, &req->res.headers, vhttp_STRLIT("conn-flow-out"), 0, NULL, conn_flow_out.base,
                          conn_flow_out.len);

    vhttp_start_response(req, &generator);
    vhttp_send(req, debug_state->json.entries,
             vhttp_memis(req->input.method.base, req->input.method.len, vhttp_STRLIT("HEAD")) ? 0 : debug_state->json.size,
             vhttp_SEND_STATE_FINAL);
    return 0;
}

void vhttp_http2_debug_state_register(vhttp_hostconf_t *conf, int hpack_enabled)
{
    vhttp_pathconf_t *pathconf = vhttp_config_register_path(conf, "/.well-known/h2/state", 0);
    struct st_vhttp_http2_debug_state_handler_t *self = (void *)vhttp_create_handler(pathconf, sizeof(*self));
    self->super.on_req = on_req;
    self->hpack_enabled = hpack_enabled;
}
