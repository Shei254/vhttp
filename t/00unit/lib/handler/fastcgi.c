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
#include "../../test.h"
#include "../../../../lib/handler/fastcgi.c"

static vhttp_context_t ctx;

static int check_params(vhttp_iovec_t *vecs, size_t *index, uint16_t request_id, const char *expected, size_t expected_len)
{
#define DECODE_UINT16(p) (((unsigned char *)&p)[0] << 8 | ((unsigned char *)&p)[1])

    char buf[4096];
    size_t offset = 0;

    while (1) {
        if (vecs[*index].len != FCGI_RECORD_HEADER_SIZE) {
            fprintf(stderr, "record too short (index: %zu)\n", *index);
            return 0;
        }
        struct st_fcgi_record_header_t *header = (void *)vecs[*index].base;
        if (header->version != FCGI_VERSION_1 || header->type != FCGI_PARAMS || header->paddingLength != 0 ||
            header->reserved != 0) {
            fprintf(stderr, "header is corrupt (index: %zu)\n", *index);
            return 0;
        }
        if (DECODE_UINT16(header->requestId) != request_id) {
            fprintf(stderr, "unexpected request id (index: %zu)\n", *index);
            return 0;
        }
        ++*index;
        if (DECODE_UINT16(header->contentLength) == 0)
            break;
        if (vecs[*index].len != DECODE_UINT16(header->contentLength)) {
            fprintf(stderr, "unexpected body size (index: %zu)\n", *index);
            return 0;
        }
        memcpy(buf + offset, vecs[*index].base, vecs[*index].len);
        offset += vecs[*index].len;
        ++*index;
    }

    if (!vhttp_memis(buf, offset, expected, expected_len)) {
        fprintf(stderr, "PARAMS content mistach\n");
        return 0;
    }

    return 1;

#undef DECODE_UINT16
}

static void test_build_request(void)
{
    vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
    vhttp_fastcgi_config_vars_t config = {5000, 0};
    iovec_vector_t vecs;
    size_t vec_index;

    conn->req.input.method = conn->req.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
    conn->req.input.scheme = conn->req.scheme = &vhttp_URL_SCHEME_HTTP;
    conn->req.input.authority = conn->req.authority = vhttp_iovec_init(vhttp_STRLIT("localhost"));
    conn->req.input.path = conn->req.path = vhttp_iovec_init(vhttp_STRLIT("/"));
    conn->req.path_normalized = conn->req.path;
    conn->req.query_at = SIZE_MAX;
    conn->req.version = 0x101;
    conn->req.hostconf = *ctx.globalconf->hosts;
    conn->req.pathconf = conn->req.hostconf->paths.entries[0];
    vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_COOKIE, NULL, vhttp_STRLIT("foo=bar"));
    vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_USER_AGENT, NULL,
                   vhttp_STRLIT("Mozilla/5.0 (X11; Linux) KHTML/4.9.1 (like Gecko) Konqueror/4.9"));

    /* build with max_record_size=65535 */
    build_request(&conn->req, &vecs, 0x1234, 65535, &config);
    ok(vhttp_memis(vecs.entries[0].base, vecs.entries[0].len,
                 vhttp_STRLIT("\x01\x01\x12\x34\x00\x08\x00\x00"
                            "\x00\x01\0\0\0\0\0\0")));
    vec_index = 1;
    ok(check_params(vecs.entries, &vec_index, 0x1234,
                    vhttp_STRLIT("\x0b\x00SCRIPT_NAME"                                                                    /* */
                               "\x09\x01PATH_INFO/"                                                                     /* */
                               "\x0c\x00QUERY_STRING"                                                                   /* */
                               "\x0b\x09REMOTE_ADDR127.0.0.1"                                                           /* */
                               "\x0b\x05REMOTE_PORT55555"                                                               /* */
                               "\x0e\x03REQUEST_METHODGET"                                                              /* */
                               "\x09\x09HTTP_HOSTlocalhost"                                                             /* */
                               "\x0b\x01REQUEST_URI/"                                                                   /* */
                               "\x0b\x09SERVER_ADDR127.0.0.1"                                                           /* */
                               "\x0b\x02SERVER_PORT80"                                                                  /* */
                               "\x0b\x07SERVER_NAMEdefault"                                                             /* */
                               "\x0f\x08SERVER_PROTOCOLHTTP/1.1"                                                        /* */
                               "\x0f\x10SERVER_SOFTWAREvhttp/1.2.1-alpha1"                                                /* */
                               "\x0f\x3fHTTP_USER_AGENTMozilla/5.0 (X11; Linux) KHTML/4.9.1 (like Gecko) Konqueror/4.9" /* */
                               "\x0b\x07HTTP_COOKIEfoo=bar"                                                             /* */
                               )));
    ok(vhttp_memis(vecs.entries[vec_index].base, vecs.entries[vec_index].len, vhttp_STRLIT("\x01\x05\x12\x34\x00\x00\x00\x00")));
    ++vec_index;
    ok(vec_index == vecs.size);

    /* build with max_record_size=64, DOCUMENT_ROOT, additional cookie, and content */
    config.document_root = vhttp_iovec_init(vhttp_STRLIT("/var/www/htdocs"));
    vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_COOKIE, NULL, vhttp_STRLIT("hoge=fuga"));
    conn->req.entity = vhttp_iovec_init(vhttp_STRLIT("The above copyright notice and this permission notice shall be included in all "
                                                 "copies or substantial portions of the Software."));
    build_request(&conn->req, &vecs, 0x1234, 64, &config);
    ok(vhttp_memis(vecs.entries[0].base, vecs.entries[0].len,
                 vhttp_STRLIT("\x01\x01\x12\x34\x00\x08\x00\x00"
                            "\x00\x01\0\0\0\0\0\0")));
    vec_index = 1;
    ok(check_params(vecs.entries, &vec_index, 0x1234,
                    vhttp_STRLIT("\x0e\x03"
                               "CONTENT_LENGTH126"   /* */
                               "\x0b\x00SCRIPT_NAME" /* */
                               "\x09\x01PATH_INFO/"  /* */
                               "\x0d\x0f"
                               "DOCUMENT_ROOT/var/www/htdocs"                                                           /* */
                               "\x0f\x10PATH_TRANSLATED/var/www/htdocs/"                                                /* */
                               "\x0c\x00QUERY_STRING"                                                                   /* */
                               "\x0b\x09REMOTE_ADDR127.0.0.1"                                                           /* */
                               "\x0b\x05REMOTE_PORT55555"                                                               /* */
                               "\x0e\x03REQUEST_METHODGET"                                                              /* */
                               "\x09\x09HTTP_HOSTlocalhost"                                                             /* */
                               "\x0b\x01REQUEST_URI/"                                                                   /* */
                               "\x0b\x09SERVER_ADDR127.0.0.1"                                                           /* */
                               "\x0b\x02SERVER_PORT80"                                                                  /* */
                               "\x0b\x07SERVER_NAMEdefault"                                                             /* */
                               "\x0f\x08SERVER_PROTOCOLHTTP/1.1"                                                        /* */
                               "\x0f\x10SERVER_SOFTWAREvhttp/1.2.1-alpha1"                                                /* */
                               "\x0f\x3fHTTP_USER_AGENTMozilla/5.0 (X11; Linux) KHTML/4.9.1 (like Gecko) Konqueror/4.9" /* */
                               "\x0b\x11HTTP_COOKIEfoo=bar;hoge=fuga"                                                   /* */
                               )));
    ok(vhttp_memis(vecs.entries[vec_index].base, vecs.entries[vec_index].len, vhttp_STRLIT("\x01\x05\x12\x34\x00\x40\x00\x00")));
    ++vec_index;
    ok(vhttp_memis(vecs.entries[vec_index].base, vecs.entries[vec_index].len,
                 vhttp_STRLIT("The above copyright notice and this permission notice shall be i")));
    ++vec_index;
    ok(vhttp_memis(vecs.entries[vec_index].base, vecs.entries[vec_index].len, vhttp_STRLIT("\x01\x05\x12\x34\x00\x3e\x00\x00")));
    ++vec_index;
    ok(vhttp_memis(vecs.entries[vec_index].base, vecs.entries[vec_index].len,
                 vhttp_STRLIT("ncluded in all copies or substantial portions of the Software.")));
    ++vec_index;
    ok(vhttp_memis(vecs.entries[vec_index].base, vecs.entries[vec_index].len, vhttp_STRLIT("\x01\x05\x12\x34\x00\x00\x00\x00")));
    ++vec_index;
    ok(vec_index == vecs.size);

    vhttp_loopback_destroy(conn);
}

void test_lib__handler__fastcgi_c()
{
    vhttp_globalconf_t globalconf;
    vhttp_hostconf_t *hostconf;
    vhttp_pathconf_t *pathconf;

    vhttp_config_init(&globalconf);
    globalconf.server_name = vhttp_iovec_init(vhttp_STRLIT("vhttp/1.2.1-alpha1"));
    hostconf = vhttp_config_register_host(&globalconf, vhttp_iovec_init(vhttp_STRLIT("default")), 65535);
    pathconf = vhttp_config_register_path(hostconf, "/", 0);

    vhttp_context_init(&ctx, test_loop, &globalconf);

    subtest("build-request", test_build_request);

    vhttp_context_dispose(&ctx);
    vhttp_config_dispose(&globalconf);
}
