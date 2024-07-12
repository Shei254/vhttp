/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include "../../test.h"
#include "../../../../lib/handler/redirect.c"

static vhttp_context_t ctx;

static int check_header(vhttp_res_t *res, const vhttp_token_t *header_name, const char *expected)
{
    ssize_t index = vhttp_find_header(&res->headers, header_name, -1);
    if (index == -1)
        return 0;
    return vhttp_lcstris(res->headers.entries[index].value.base, res->headers.entries[index].value.len, expected, strlen(expected));
}

void test_lib__handler__redirect_c()
{
    vhttp_globalconf_t globalconf;
    vhttp_hostconf_t *hostconf;
    vhttp_pathconf_t *pathconf;

    vhttp_config_init(&globalconf);
    hostconf = vhttp_config_register_host(&globalconf, vhttp_iovec_init(vhttp_STRLIT("default")), 65535);
    pathconf = vhttp_config_register_path(hostconf, "/", 0);
    vhttp_redirect_register(pathconf, 0, 301, "https://example.com/bar/");

    vhttp_context_init(&ctx, test_loop, &globalconf);

    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, vhttp_TOKEN_LOCATION, "https://example.com/bar/"));
        ok(conn->body->size != 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/abc"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, vhttp_TOKEN_LOCATION, "https://example.com/bar/abc"));
        ok(conn->body->size != 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("HEAD"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, vhttp_TOKEN_LOCATION, "https://example.com/bar/"));
        ok(conn->body->size == 0);
        vhttp_loopback_destroy(conn);
    }

    vhttp_context_dispose(&ctx);
    vhttp_config_dispose(&globalconf);
}
