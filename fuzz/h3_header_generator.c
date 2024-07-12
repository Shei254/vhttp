/*
 * Copyright (c) 2021 Fastly, Inc.
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

#include <stdio.h>
#include <getopt.h>

#include "vhttp.h"
#include "vhttp/qpack.h"

static void usage(const char *progname)
{
    fprintf(stderr,
            "%s: generates HTTP/3 HEADERS frame, including QPACK-encoded payload\n"
            "\n"
            "Usage: %s [options] <output-file>\n"
            "Options:\n"
            "  -H <name:value>\n"
            "               adds a request header\n"
            "  -x <authority>\n"
            "               specifies the authority value (default: \"www.example.com\")\n"
            "  -p <path>    specifies the path (default: \"/\")\n"
            "  -h           prints this help\n"
            "\n",
            progname, progname);
}

int main(int argc, char *argv[])
{
    FILE *fp = NULL;
    int opt, ret = 1;
    vhttp_mem_pool_t pool;
    vhttp_headers_t headers = {NULL};
    const char *progname = argv[0];
    const char *authority = "www.example.com";
    const char *path = "/";

    vhttp_mem_init_pool(&pool);

    while ((opt = getopt(argc, argv, "H:h:x:p:")) != -1) {
        switch (opt) {
        case 'H': {
            /* code excerpted from httpclient.c */
            const char *colon, *value_start;
            if ((colon = index(optarg, ':')) == NULL) {
                fprintf(stderr, "no `:` found in -H\n");
                return 1;
            }
            for (value_start = colon + 1; *value_start == ' ' || *value_start == '\t'; ++value_start)
                ;
            vhttp_iovec_t name = vhttp_iovec_init(optarg, colon - optarg);
            vhttp_iovec_t value = vhttp_iovec_init(value_start, strlen(value_start));
            vhttp_add_header_by_str(&pool, &headers, name.base, name.len, 1, NULL, value.base, value.len);
        } break;

        case 'h':
            usage(progname);
            ret = 1;
            goto Exit;
            break;

        case 'x':
            authority = optarg;
            break;

        case 'p':
            path = optarg;
            break;

        default:
            usage(progname);
            goto Exit;
        }
    }
    argc -= optind;
    argv += optind;

    if (argc < 1) {
        usage(progname);
        goto Exit;
    }

    fp = fopen(argv[0], "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", argv[0], strerror(errno));
        goto Exit;
    }

    vhttp_qpack_encoder_t *enc = vhttp_qpack_create_encoder(4096, 10);
    vhttp_iovec_t headers_frame = vhttp_qpack_flatten_request(
        enc, &pool, 0, NULL, vhttp_iovec_init(vhttp_STRLIT("GET")), &vhttp_URL_SCHEME_HTTPS, vhttp_iovec_init(authority, strlen(authority)),
        vhttp_iovec_init(path, strlen(path)), vhttp_iovec_init(NULL, 0), headers.entries, headers.size, vhttp_iovec_init(NULL, 0));
    fwrite(headers_frame.base, headers_frame.len, 1, fp);

    vhttp_qpack_destroy_encoder(enc);

    ret = 0;
Exit:
    vhttp_mem_clear_pool(&pool);

    if (fp != NULL)
        fclose(fp);

    return ret;
}
