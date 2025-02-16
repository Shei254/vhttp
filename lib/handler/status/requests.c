/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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

struct st_requests_status_ctx_t {
    vhttp_logconf_t *logconf;
    vhttp_iovec_t req_data;
    pthread_mutex_t mutex;
};

struct st_collect_req_status_cbdata_t {
    vhttp_logconf_t *logconf;
    vhttp_buffer_t *buffer;
};

static int collect_req_status(vhttp_req_t *req, void *_cbdata)
{
    struct st_collect_req_status_cbdata_t *cbdata = _cbdata;

    /* collect log */
    char buf[4096];
    size_t len = sizeof(buf);
    char *logline = vhttp_log_request(cbdata->logconf, req, &len, buf);
    assert(len != 0);
    --len; /* omit trailing LF */

    /* append to buffer */
    if ((vhttp_buffer_try_reserve(&cbdata->buffer, len + 3)).base == NULL) {
        if (logline != buf)
            free(logline);
        return -1;
    }
    memcpy(cbdata->buffer->bytes + cbdata->buffer->size, logline, len);
    cbdata->buffer->size += len;

    if (logline != buf)
        free(logline);

    return 0;
}

static void requests_status_per_thread(void *priv, vhttp_context_t *ctx)
{
    struct st_requests_status_ctx_t *rsc = priv;
    struct st_collect_req_status_cbdata_t cbdata = {rsc->logconf};

    /* we encountered an error at init() time, return early */
    if (rsc->logconf == NULL)
        return;

    vhttp_buffer_init(&cbdata.buffer, &vhttp_socket_buffer_prototype);

    vhttp_CONN_LIST_FOREACH(vhttp_conn_t * conn, ({&ctx->_conns.active, &ctx->_conns.idle, &ctx->_conns.shutdown}), {
        if (conn->callbacks->foreach_request(conn, collect_req_status, &cbdata) != 0) {
            vhttp_buffer_dispose(&cbdata.buffer);
            return;
        }
    });

    /* concat JSON elements */
    if (cbdata.buffer->size != 0) {
        pthread_mutex_lock(&rsc->mutex);
        if (rsc->req_data.len == 0)
            vhttp_buffer_consume(&cbdata.buffer, 1); /* skip preceeding comma */
        rsc->req_data.base = vhttp_mem_realloc(rsc->req_data.base, rsc->req_data.len + cbdata.buffer->size);
        memcpy(rsc->req_data.base + rsc->req_data.len, cbdata.buffer->bytes, cbdata.buffer->size);
        rsc->req_data.len += cbdata.buffer->size;
        pthread_mutex_unlock(&rsc->mutex);
    }

    vhttp_buffer_dispose(&cbdata.buffer);
}

static void *requests_status_init(void)
{
    struct st_requests_status_ctx_t *rsc = vhttp_mem_alloc(sizeof(*rsc));
    char errbuf[256];

#define ELEMENT(key, expr) "\"" key "\": \"" expr "\""
#define X_ELEMENT(id) ELEMENT(id, "%{" id "}x")
#define SEPARATOR ", "
    const char *fmt = ",\n  {"
        /* combined_log */
        ELEMENT("host", "%h") SEPARATOR ELEMENT("user", "%u") SEPARATOR ELEMENT("at", "%{%Y%m%dT%H%M%S}t.%{usec_frac}t%{%z}t")
            SEPARATOR ELEMENT("method", "%m") SEPARATOR ELEMENT("path", "%U") SEPARATOR ELEMENT("query", "%q")
                SEPARATOR ELEMENT("protocol", "%H") SEPARATOR ELEMENT("referer", "%{Referer}i")
                    SEPARATOR ELEMENT("user-agent", "%{User-agent}i") SEPARATOR
                        /* time */
                        X_ELEMENT("connect-time") SEPARATOR X_ELEMENT("request-header-time")
                            SEPARATOR X_ELEMENT("request-body-time") SEPARATOR X_ELEMENT("request-total-time")
                                SEPARATOR X_ELEMENT("process-time") SEPARATOR X_ELEMENT("response-time") SEPARATOR
                                    /* connection */
                                    X_ELEMENT("connection-id") SEPARATOR X_ELEMENT("ssl.protocol-version")
                                        SEPARATOR X_ELEMENT("ssl.session-reused") SEPARATOR X_ELEMENT("ssl.cipher")
                                            SEPARATOR X_ELEMENT("ssl.cipher-bits") SEPARATOR X_ELEMENT("ssl.session-ticket")
                                                SEPARATOR X_ELEMENT("ssl.server-name") SEPARATOR
                                                    /* http1 */
                                                    X_ELEMENT("http1.request-index") SEPARATOR
                                                        /* http2 */
                                                        X_ELEMENT("http2.stream-id")
                                                            SEPARATOR X_ELEMENT("http2.priority.received.exclusive")
                                                                SEPARATOR X_ELEMENT("http2.priority.received.parent")
                                                                    SEPARATOR X_ELEMENT("http2.priority.received.weight")
                                                                        SEPARATOR X_ELEMENT("http2.priority.actual.parent")
                                                                            SEPARATOR X_ELEMENT("http2.priority.actual.weight")
                                                                                SEPARATOR
                                                                                    /* misc */
                                                                                    ELEMENT("authority", "%V")
        /* end */
        "}";
#undef ELEMENT
#undef X_ELEMENT
#undef SEPARATOR

    /* compile logconf */
    if ((rsc->logconf = vhttp_logconf_compile(fmt, vhttp_LOGCONF_ESCAPE_JSON, errbuf)) == NULL)
        /* log format compilation error is an internal logic flaw, therefore we need not send the details to the client */
        vhttp_error_printf("[lib/handler/status/requests.c] failed to compile log format: %s", errbuf);

    rsc->req_data = (vhttp_iovec_t){NULL};
    pthread_mutex_init(&rsc->mutex, NULL);

    return rsc;
}

static vhttp_iovec_t requests_status_final(void *priv, vhttp_globalconf_t *gconf, vhttp_req_t *req)
{
    vhttp_iovec_t ret = {NULL};
    struct st_requests_status_ctx_t *rsc = priv;

    if (rsc->logconf != NULL) {
        ret = vhttp_concat(&req->pool, vhttp_iovec_init(vhttp_STRLIT(",\n \"requests\": [")), rsc->req_data,
                         vhttp_iovec_init(vhttp_STRLIT("\n ]")));
        vhttp_logconf_dispose(rsc->logconf);
    }
    free(rsc->req_data.base);
    pthread_mutex_destroy(&rsc->mutex);

    free(rsc);
    return ret;
}

vhttp_status_handler_t vhttp_requests_status_handler = {
    {vhttp_STRLIT("requests")}, requests_status_final, requests_status_init, requests_status_per_thread};
