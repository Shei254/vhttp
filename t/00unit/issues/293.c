/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <stdio.h>
#include "../test.h"

static vhttp_context_t ctx;

static void register_authority(vhttp_globalconf_t *globalconf, vhttp_iovec_t host, uint16_t port)
{
    static vhttp_iovec_t x_authority = {vhttp_STRLIT("x-authority")};

    vhttp_hostconf_t *hostconf = vhttp_config_register_host(globalconf, host, port);
    vhttp_pathconf_t *pathconf = vhttp_config_register_path(hostconf, "/", 0);
    vhttp_file_register(pathconf, "t/00unit/assets", NULL, NULL, 0);

    char *authority = vhttp_mem_alloc(host.len + sizeof(":" vhttp_UINT16_LONGEST_STR));
    sprintf(authority, "%.*s:%" PRIu16, (int)host.len, host.base, port);
    vhttp_headers_command_t *cmds = vhttp_mem_alloc(sizeof(*cmds) * 2);
    vhttp_headers_command_arg_t *args = vhttp_mem_alloc(sizeof(*args));
    *args = (vhttp_headers_command_arg_t){&x_authority, {authority, strlen(authority)}};
    cmds[0] = (vhttp_headers_command_t){vhttp_HEADERS_CMD_ADD, args, 1};
    cmds[1] = (vhttp_headers_command_t){vhttp_HEADERS_CMD_NULL};
    vhttp_headers_register(pathconf, cmds);
}

static void check(const vhttp_url_scheme_t *scheme, const char *host, const char *expected)
{
    vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);

    conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
    conn->req.input.scheme = scheme;
    conn->req.input.authority = vhttp_iovec_init(host, strlen(host));
    conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
    vhttp_loopback_run_loop(conn);
    ok(conn->req.res.status == 200);

    ssize_t index = vhttp_find_header_by_str(&conn->req.res.headers, vhttp_STRLIT("x-authority"), -1);
    ok(index != -1);

    if (index != -1) {
        ok(vhttp_memis(conn->req.res.headers.entries[index].value.base, conn->req.res.headers.entries[index].value.len, expected,
                     strlen(expected)));
    }

    vhttp_loopback_destroy(conn);
}

void test_issues293()
{
    vhttp_globalconf_t globalconf;

    vhttp_config_init(&globalconf);

    /* register two hosts, using 80 and 443 */
    register_authority(&globalconf, vhttp_iovec_init(vhttp_STRLIT("default")), 65535);
    register_authority(&globalconf, vhttp_iovec_init(vhttp_STRLIT("host1")), 80);
    register_authority(&globalconf, vhttp_iovec_init(vhttp_STRLIT("host1")), 443);
    register_authority(&globalconf, vhttp_iovec_init(vhttp_STRLIT("host2")), 80);
    register_authority(&globalconf, vhttp_iovec_init(vhttp_STRLIT("host2")), 443);
    register_authority(&globalconf, vhttp_iovec_init(vhttp_STRLIT("host3")), 65535);

    vhttp_context_init(&ctx, test_loop, &globalconf);

    /* run the tests */
    check(&vhttp_URL_SCHEME_HTTP, "host1", "host1:80");
    check(&vhttp_URL_SCHEME_HTTPS, "host1", "host1:443");
    check(&vhttp_URL_SCHEME_HTTP, "host2", "host2:80");
    check(&vhttp_URL_SCHEME_HTTPS, "host2", "host2:443");

    /* supplied port number in the Host header must be preferred */
    check(&vhttp_URL_SCHEME_HTTP, "host1:80", "host1:80");
    check(&vhttp_URL_SCHEME_HTTP, "host1:443", "host1:443");
    check(&vhttp_URL_SCHEME_HTTPS, "host1:80", "host1:80");
    check(&vhttp_URL_SCHEME_HTTPS, "host1:443", "host1:443");
    check(&vhttp_URL_SCHEME_HTTP, "host2:80", "host2:80");
    check(&vhttp_URL_SCHEME_HTTP, "host2:443", "host2:443");
    check(&vhttp_URL_SCHEME_HTTPS, "host2:80", "host2:80");
    check(&vhttp_URL_SCHEME_HTTPS, "host2:443", "host2:443");

    /* host-level conf without default port */
    check(&vhttp_URL_SCHEME_HTTP, "host3", "host3:65535");
    check(&vhttp_URL_SCHEME_HTTPS, "host3", "host3:65535");
    check(&vhttp_URL_SCHEME_HTTP, "host3", "host3:65535");
    check(&vhttp_URL_SCHEME_HTTPS, "host3", "host3:65535");
    check(&vhttp_URL_SCHEME_HTTP, "host3:80", "host3:65535");
    check(&vhttp_URL_SCHEME_HTTPS, "host3:80", "default:65535");
    check(&vhttp_URL_SCHEME_HTTP, "host3:443", "default:65535");
    check(&vhttp_URL_SCHEME_HTTPS, "host3:443", "host3:65535");

    /* upper-case */
    check(&vhttp_URL_SCHEME_HTTP, "HoST1", "host1:80");
    check(&vhttp_URL_SCHEME_HTTP, "HoST1:80", "host1:80");
    check(&vhttp_URL_SCHEME_HTTPS, "HoST1", "host1:443");
    check(&vhttp_URL_SCHEME_HTTPS, "HoST1:443", "host1:443");

    vhttp_context_dispose(&ctx);
    vhttp_config_dispose(&globalconf);
}
