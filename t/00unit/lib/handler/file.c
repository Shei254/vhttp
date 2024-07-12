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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/handler/file.c"

static vhttp_context_t ctx;

static int check_header(vhttp_res_t *res, const vhttp_token_t *header_name, const char *expected)
{
    ssize_t index = vhttp_find_header(&res->headers, header_name, -1);
    if (index == -1)
        return 0;
    return vhttp_lcstris(res->headers.entries[index].value.base, res->headers.entries[index].value.len, expected, strlen(expected));
}

static int check_multirange_body(char *resbody, const char *boundary, const vhttp_iovec_t *expected, size_t partlen)
{
    char *bptr = resbody;
    const vhttp_iovec_t *eptr = expected;
    int not_first_line = 0;
    while (partlen--) {
        if (not_first_line) {
            if (!vhttp_memis(bptr, 2, vhttp_STRLIT("\r\n")))
                return 0;
            bptr += 2;
        } else
            not_first_line = 1;
        if (!vhttp_memis(bptr, 2, vhttp_STRLIT("--")))
            return 0;
        bptr += 2;
        if (!vhttp_memis(bptr, BOUNDARY_SIZE, boundary, BOUNDARY_SIZE))
            return 0;
        bptr += 20;
        if (!vhttp_memis(bptr, 2, vhttp_STRLIT("\r\n")))
            return 0;
        bptr += 2;
        if (!vhttp_memis(bptr, eptr->len, eptr->base, eptr->len))
            return 0;
        bptr += eptr->len;
        eptr++;
    }
    if (!vhttp_memis(bptr, 4, vhttp_STRLIT("\r\n--")))
        return 0;
    bptr += 4;
    if (!vhttp_memis(bptr, BOUNDARY_SIZE, boundary, BOUNDARY_SIZE))
        return 0;
    bptr += 20;
    if (!vhttp_memis(bptr, 4, vhttp_STRLIT("--\r\n")))
        return 0;
    return 1;
}

static void test_process_range(void)
{
    vhttp_mem_pool_t testpool;
    size_t ret, *ranges;
    vhttp_iovec_t testrange;
    vhttp_mem_init_pool(&testpool);

    { /* check single range within filesize */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=, 0-10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 0);
        ok(*ranges == 11);
    }

    { /* check single range with only start */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=60-"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 60);
        ok(*ranges == 40);
    }

    { /* check single suffix range */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=-10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 90);
        ok(*ranges == 10);
    }

    { /* this and next two check multiple ranges within filesize */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=0-10, -10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 0);
        ok(*ranges++ == 11);
        ok(*ranges++ == 90);
        ok(*ranges == 10);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=0-0, 20-89"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 0);
        ok(*ranges++ == 1);
        ok(*ranges++ == 20);
        ok(*ranges == 70);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=-10,-20"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 90);
        ok(*ranges++ == 10);
        ok(*ranges++ == 80);
        ok(*ranges++ == 20);
    }

    { /* check ranges entirely out of filesize */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=100-102"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    { /* check ranges with "negative" length */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=70-21"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    { /* check ranges with one side inside filesize */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=90-102"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 90);
        ok(*ranges == 10);
    }

    { /* check suffix range larger than filesize */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=-200"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 0);
        ok(*ranges == 100);
    }

    { /* check multiple ranges with unsatisfiable ranges, but also contain satisfiable ranges */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=100-102,  90-102, 72-30,-22, 95-"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 3);
        ok(*ranges++ == 90);
        ok(*ranges++ == 10);
        ok(*ranges++ == 78);
        ok(*ranges++ == 22);
        ok(*ranges++ == 95);
        ok(*ranges++ == 5);
    }

    { /* this and next 6 check malformed ranges */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes 20-1002"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes="));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bsdfeadsfjwleakjf"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=100-102, 90-102, -72-30,-22,95-"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=10-12-13, 90-102, -72, -22, 95-"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=100-102, 90-102, 70-39, -22$"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=-0"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    { /* check same ranges with different filesize */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=20-200"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 1);
        ok(*ranges++ == 20);
        ok(*ranges == 80);
    }

    {
        ranges = process_range(&testpool, &testrange, 1000, &ret);
        ok(ret == 1);
        ok(*ranges++ == 20);
        ok(*ranges == 181);
    }

    { /* check a range with plenty of WS and COMMA */
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=,\t,1-3 ,, ,5-9,"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 1);
        ok(*ranges++ == 3);
        ok(*ranges++ == 5);
        ok(*ranges == 5);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes= 1-3"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=1-3 5-10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ranges == NULL);
    }

    {
        testrange = vhttp_iovec_init(vhttp_STRLIT("bytes=1-\t,5-10"));
        ranges = process_range(&testpool, &testrange, 100, &ret);
        ok(ret == 2);
        ok(*ranges++ == 1);
        ok(*ranges++ == 99);
        ok(*ranges++ == 5);
        ok(*ranges == 6);
    }

    vhttp_mem_clear_pool(&testpool);
}

static void test_if_modified_since(void)
{
    char lm_date[vhttp_TIMESTR_RFC1123_LEN + 1];

    { /* obtain last-modified */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t lm_index;
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        if ((lm_index = vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_LAST_MODIFIED, -1)) == -1) {
            ok(0);
            return;
        }
        ok(conn->req.res.headers.entries[lm_index].value.len == vhttp_TIMESTR_RFC1123_LEN);
        memcpy(lm_date, conn->req.res.headers.entries[lm_index].value.base, vhttp_TIMESTR_RFC1123_LEN);
        lm_date[vhttp_TIMESTR_RFC1123_LEN] = '\0';
        vhttp_loopback_destroy(conn);
    }

    { /* send if-modified-since using the obtained last-modified */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_MODIFIED_SINCE, NULL, lm_date, vhttp_TIMESTR_RFC1123_LEN);
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        ok(vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_ETAG, -1) != -1);
        vhttp_loopback_destroy(conn);
    }

    { /* send if-modified-since using an old date */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_MODIFIED_SINCE, NULL,
                       vhttp_STRLIT("Sun, 06 Nov 1994 08:49:37 GMT"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        vhttp_loopback_destroy(conn);
    }

    { /* send if-modified-since using a date in the future */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_MODIFIED_SINCE, NULL,
                       vhttp_STRLIT("Wed, 18 May 2033 12:33:20 GMT"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        ok(vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_ETAG, -1) != -1);
        vhttp_loopback_destroy(conn);
    }
}

static void test_if_match(void)
{
    vhttp_iovec_t etag = {NULL};

    { /* obtain etag */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t etag_index;
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        if ((etag_index = vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_ETAG, -1)) == -1) {
            ok(0);
            return;
        }
        etag = vhttp_strdup(NULL, conn->req.res.headers.entries[etag_index].value.base,
                          conn->req.res.headers.entries[etag_index].value.len);
        vhttp_loopback_destroy(conn);
    }

    { /* send if-non-match using the obtained etag */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_NONE_MATCH, NULL, etag.base, etag.len);
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 304);
        ok(conn->body->size == 0);
        vhttp_loopback_destroy(conn);
    }

    free(etag.base);
}

static void test_if_range(void)
{
    vhttp_iovec_t etag = {NULL}, weak_etag = {NULL};
    char lm_date[vhttp_TIMESTR_RFC1123_LEN + 1];
    size_t body_size;

    { /* obtain etag */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t etag_index;
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        if ((etag_index = vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_ETAG, -1)) == -1) {
            ok(0);
            return;
        }
        etag = vhttp_strdup(NULL, conn->req.res.headers.entries[etag_index].value.base,
                          conn->req.res.headers.entries[etag_index].value.len);
        weak_etag.base = malloc(etag.len + 2);
        weak_etag.len = etag.len + 2;
        weak_etag.base[0] = 'W';
        weak_etag.base[1] = '/';
        memcpy(weak_etag.base + 2, etag.base, etag.len);
        body_size = conn->body->size;
        vhttp_loopback_destroy(conn);
    }

    { /* obtain last-modified */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t lm_index;
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(conn->body->size == body_size);
        if ((lm_index = vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_LAST_MODIFIED, -1)) == -1) {
            ok(0);
            return;
        }
        ok(conn->req.res.headers.entries[lm_index].value.len == vhttp_TIMESTR_RFC1123_LEN);
        memcpy(lm_date, conn->req.res.headers.entries[lm_index].value.base, vhttp_TIMESTR_RFC1123_LEN);
        lm_date[vhttp_TIMESTR_RFC1123_LEN] = '\0';
        vhttp_loopback_destroy(conn);
    }

    { /* send if-range with no range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_RANGE, NULL, etag.base, etag.len);
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(conn->body->size == body_size);
        vhttp_loopback_destroy(conn);
    }

    { /* send obtained etag as if-range with range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_RANGE, NULL, etag.base, etag.len);
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=0-10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 0-10/1000"));
        ok(conn->body->size == 11);
        ok(memcmp(conn->body->bytes, "123456789\n1", 11) == 0);
        vhttp_loopback_destroy(conn);
    }

    { /* send obtained last-modified as if-range with range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_RANGE, NULL, lm_date, vhttp_TIMESTR_RFC1123_LEN);
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=0-10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 0-10/1000"));
        ok(conn->body->size == 11);
        ok(memcmp(conn->body->bytes, "123456789\n1", 11) == 0);
        vhttp_loopback_destroy(conn);
    }

    { /* send weak etag as if-range with range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_RANGE, NULL, weak_etag.base, weak_etag.len);
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=0-10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == body_size);
        vhttp_loopback_destroy(conn);
    }

    { /* send different etag as if-range with range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        etag.base[1] = 'z';
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_RANGE, NULL, etag.base, etag.len);
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=0-10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == body_size);
        vhttp_loopback_destroy(conn);
    }

    { /* send if-range using an old date */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_RANGE, NULL, vhttp_STRLIT("Sun, 06 Nov 1994 08:49:37 GMT"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=0-10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == body_size);
        vhttp_loopback_destroy(conn);
    }

    { /* send if-range using a date in the future */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_IF_RANGE, NULL, vhttp_STRLIT("Wed, 18 May 2033 12:33:20 GMT"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=0-10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 0-10/1000"));
        ok(conn->body->size == 11);
        ok(memcmp(conn->body->bytes, "123456789\n1", 11) == 0);
        vhttp_loopback_destroy(conn);
    }

    free(etag.base);
    free(weak_etag.base);
}

static void test_range_req(void)
{
    { /* check if accept-ranges is "bytes" */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        if (check_header(&conn->req.res, vhttp_TOKEN_ACCEPT_RANGES, "none")) {
            ok(1);
            return;
        }
        ok(check_header(&conn->req.res, vhttp_TOKEN_ACCEPT_RANGES, "bytes"));
        ok(conn->body->size == 1000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "dfd3ae1f5c475555fad62efe42e07309fa45f2ed") == 0);
        vhttp_loopback_destroy(conn);
    }
    { /* check a normal single range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=0-10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 0-10/1000"));
        ok(conn->body->size == 11);
        ok(memcmp(conn->body->bytes, "123456789\n1", 11) == 0);
        vhttp_loopback_destroy(conn);
    }
    { /* check an over range single range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=990-1100"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 990-999/1000"));
        ok(conn->body->size == 10);
        ok(memcmp(conn->body->bytes, "123456789\n", 10) == 0);
        vhttp_loopback_destroy(conn);
    }
    { /* check a single range without end */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=989-"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 989-999/1000"));
        ok(conn->body->size == 11);
        ok(memcmp(conn->body->bytes, "\n123456789\n", 11) == 0);
        vhttp_loopback_destroy(conn);
    }
    { /* check a single suffix range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=-21"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 979-999/1000"));
        ok(conn->body->size == 21);
        ok(memcmp(conn->body->bytes, "\n123456789\n123456789\n", 21) == 0);
        vhttp_loopback_destroy(conn);
    }
    { /* check a single suffix range over filesize */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=-2100"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 0-999/1000"));
        ok(conn->body->size == 1000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "dfd3ae1f5c475555fad62efe42e07309fa45f2ed") == 0);
        vhttp_loopback_destroy(conn);
    }
    { /* malformed range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=-0-10, 9-, -10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("requested range not satisfiable")));
        vhttp_loopback_destroy(conn);
    }
    { /* malformed range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=0-10-12, 9-, -10"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("requested range not satisfiable")));
        vhttp_loopback_destroy(conn);
    }
    { /* malformed range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytfasdf"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("requested range not satisfiable")));
        vhttp_loopback_destroy(conn);
    }
    { /* half-malformed range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=-0"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("requested range not satisfiable")));
        vhttp_loopback_destroy(conn);
    }
    { /* single range over filesize */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=1000-1001"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("requested range not satisfiable")));
        vhttp_loopback_destroy(conn);
    }
    { /* single range with "negative" length */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=900-100"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 416);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes */1000"));
        ok(conn->body->size == strlen("requested range not satisfiable"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("requested range not satisfiable")));
        vhttp_loopback_destroy(conn);
    }
    { /* check a half-malformed range with a normal range */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=-0, 0-0"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_RANGE, "bytes 0-0/1000"));
        ok(conn->body->size == 1);
        ok(memcmp(conn->body->bytes, "1", 1) == 0);
        vhttp_loopback_destroy(conn);
    }
    { /* multiple ranges */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t content_type_index;
        vhttp_iovec_t content_type, expected[2] = {{NULL}};
        char boundary[BOUNDARY_SIZE + 1];
        size_t mimebaselen = strlen("multipart/byteranges; boundary=");
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=-0, 0-9,-11"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        if ((content_type_index = vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_CONTENT_TYPE, -1)) == -1) {
            ok(0);
            return;
        }
        content_type = conn->req.res.headers.entries[content_type_index].value;
        ok(vhttp_memis(content_type.base, mimebaselen, "multipart/byteranges; boundary=", mimebaselen));
        memcpy(boundary, content_type.base + mimebaselen, BOUNDARY_SIZE);
        boundary[BOUNDARY_SIZE] = 0;
        expected[0].base = vhttp_mem_alloc_pool(&conn->req.pool, char, 256);
        expected[0].len =
            sprintf(expected[0].base, "Content-Type: %s\r\nContent-Range: bytes 0-9/1000\r\n\r\n%s", "text/plain", "123456789\n");
        expected[1].base = vhttp_mem_alloc_pool(&conn->req.pool, char, 256);
        expected[1].len = sprintf(expected[1].base, "Content-Type: %s\r\nContent-Range: bytes 989-999/1000\r\n\r\n%s", "text/plain",
                                  "\n123456789\n");
        ok(vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_CONTENT_RANGE, -1) == -1);
        ok(conn->body->size == conn->req.res.content_length);
        ok(check_multirange_body(conn->body->bytes, boundary, expected, 2));
        vhttp_loopback_destroy(conn);
    }
    { /* multiple ranges with plenty of WS and COMMA */
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        ssize_t content_type_index;
        vhttp_iovec_t content_type, expected[2] = {{NULL}};
        char boundary[BOUNDARY_SIZE + 1];
        size_t mimebaselen = strlen("multipart/byteranges; boundary=");
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_add_header(&conn->req.pool, &conn->req.headers, vhttp_TOKEN_RANGE, NULL, vhttp_STRLIT("bytes=,\t,1-3 ,, ,5-9,"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 206);
        if ((content_type_index = vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_CONTENT_TYPE, -1)) == -1) {
            ok(0);
            return;
        }
        content_type = conn->req.res.headers.entries[content_type_index].value;
        ok(vhttp_memis(content_type.base, mimebaselen, "multipart/byteranges; boundary=", mimebaselen));
        memcpy(boundary, content_type.base + mimebaselen, BOUNDARY_SIZE);
        boundary[BOUNDARY_SIZE] = 0;
        expected[0].base = vhttp_mem_alloc_pool(&conn->req.pool, char, 256);
        expected[0].len =
            sprintf(expected[0].base, "Content-Type: %s\r\nContent-Range: bytes 1-3/1000\r\n\r\n%s", "text/plain", "234");
        expected[1].base = vhttp_mem_alloc_pool(&conn->req.pool, char, 256);
        expected[1].len =
            sprintf(expected[1].base, "Content-Type: %s\r\nContent-Range: bytes 5-9/1000\r\n\r\n%s", "text/plain", "6789\n");
        ok(vhttp_find_header(&conn->req.res.headers, vhttp_TOKEN_CONTENT_RANGE, -1) == -1);
        ok(conn->body->size == conn->req.res.content_length);
        ok(check_multirange_body(conn->body->bytes, boundary, expected, 2));
        vhttp_loopback_destroy(conn);
    }
}

static void test_strong_etag_cmp()
{
    /* example from RFC 7232 */
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("W/\"1\""), vhttp_STRLIT("W/\"1\"")));
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("W/\"1\""), vhttp_STRLIT("W/\"2\"")));
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("W/\"1\""), vhttp_STRLIT("\"1\"")));
    ok(vhttp_filecache_compare_etag_strong(vhttp_STRLIT("\"1\""), vhttp_STRLIT("\"1\"")));
    /* illegal etags */
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("\"1"), vhttp_STRLIT("\"1\"")));
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("\"1\""), vhttp_STRLIT("\"1")));
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("\"1"), vhttp_STRLIT("\"1")));
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("1\""), vhttp_STRLIT("\"1\"")));
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("\"1\""), vhttp_STRLIT("1\"")));
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT("1\""), vhttp_STRLIT("1\"")));
    ok(!vhttp_filecache_compare_etag_strong(vhttp_STRLIT(""), vhttp_STRLIT("")));
}

void test_lib__handler__file_c()
{
    vhttp_globalconf_t globalconf;
    vhttp_hostconf_t *hostconf;
    vhttp_pathconf_t *pathconf;

    vhttp_config_init(&globalconf);
    hostconf = vhttp_config_register_host(&globalconf, vhttp_iovec_init(vhttp_STRLIT("default")), 65535);
    pathconf = vhttp_config_register_path(hostconf, "/", 0);
    vhttp_file_register(pathconf, "t/00unit/assets", NULL, NULL, 0);

    vhttp_context_init(&ctx, test_loop, &globalconf);

    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("HEAD"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/html"));
        ok(conn->body->size == 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/html"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("hello html\n")));
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("HEAD"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/index.html"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/html"));
        ok(conn->body->size == 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/index.html"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/html"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("hello html\n")));
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("HEAD"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000.txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 1000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "dfd3ae1f5c475555fad62efe42e07309fa45f2ed") == 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("HEAD"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000000.txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/1000000.txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 1000000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "00c8ab71d0914dce6a1ec2eaa0fda0df7044b2a2") == 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("HEAD"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/index_txt/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(conn->body->size == 0);
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/index_txt/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(check_header(&conn->req.res, vhttp_TOKEN_CONTENT_TYPE, "text/plain"));
        ok(vhttp_memis(conn->body->bytes, conn->body->size, vhttp_STRLIT("hello text\n")));
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("HEAD"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/index_txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, vhttp_TOKEN_LOCATION, "/index_txt/"));
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/index_txt"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, vhttp_TOKEN_LOCATION, "/index_txt/"));
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("HEAD"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/index_txt_as_dir/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, vhttp_TOKEN_LOCATION, "/index_txt_as_dir/index.txt/"));
        vhttp_loopback_destroy(conn);
    }
    {
        vhttp_loopback_conn_t *conn = vhttp_loopback_create(&ctx, ctx.globalconf->hosts);
        conn->req.input.method = vhttp_iovec_init(vhttp_STRLIT("GET"));
        conn->req.input.path = vhttp_iovec_init(vhttp_STRLIT("/index_txt_as_dir/"));
        vhttp_loopback_run_loop(conn);
        ok(conn->req.res.status == 301);
        ok(check_header(&conn->req.res, vhttp_TOKEN_LOCATION, "/index_txt_as_dir/index.txt/"));
        vhttp_loopback_destroy(conn);
    }
    subtest("if-modified-since", test_if_modified_since);
    subtest("if-match", test_if_match);
    subtest("process_range()", test_process_range);
    subtest("range request", test_range_req);
    subtest("if-range", test_if_range);
    subtest("strong etag comparison", test_strong_etag_cmp);

    vhttp_context_dispose(&ctx);
    vhttp_config_dispose(&globalconf);
}
