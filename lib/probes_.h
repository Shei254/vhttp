/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
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
#ifndef vhttp__probes_h
#define vhttp__probes_h

#include "picotls.h"

#define vhttp_LOG(_type, _block) PTLS_LOG(vhttp, _type, _block)
#define vhttp_LOG_CONN(_type, _conn, _block)                                                                                         \
    do {                                                                                                                           \
        if (!ptls_log.is_active)                                                                                                   \
            break;                                                                                                                 \
        vhttp_conn_t *conn_ = (_conn);                                                                                               \
        if (conn_->callbacks->skip_tracing(conn_))                                                                                 \
            break;                                                                                                                 \
        PTLS_LOG__DO_LOG(vhttp, _type, {                                                                                             \
            PTLS_LOG_ELEMENT_UNSIGNED(conn_id, conn_->id);                                                                         \
            do {                                                                                                                   \
                _block                                                                                                             \
            } while (0);                                                                                                           \
        });                                                                                                                        \
    } while (0)

/* This file is placed under lib, and must only be included from the source files of the vhttp / libvhttp, because vhttp_USE_DTRACE is a
 * symbol available only during the build phase of vhttp.  That's fine, because only vhttp / libvhttp has the sole right to define probes
 * belonging to the vhttp namespace.
 */
#if vhttp_USE_DTRACE

#include "picotls.h"
/* as probes_.h is used by files under lib/common, structures that are specific to the server-side implementation have to be
 * forward-declared. */
struct st_vhttp_conn_t;
struct st_vhttp_tunnel_t;
#include "vhttp-probes.h"

#define vhttp_CONN_IS_PROBED(label, conn) (PTLS_UNLIKELY(vhttp_##label##_ENABLED()) && !conn->callbacks->skip_tracing(conn))

#define vhttp_PROBE_CONN0(label, conn)                                                                                               \
    do {                                                                                                                           \
        vhttp_conn_t *_conn = (conn);                                                                                                \
        if (vhttp_CONN_IS_PROBED(label, _conn)) {                                                                                    \
            vhttp_##label(_conn->id);                                                                                                \
        }                                                                                                                          \
    } while (0)

#define vhttp_PROBE_CONN(label, conn, ...)                                                                                           \
    do {                                                                                                                           \
        vhttp_conn_t *_conn = (conn);                                                                                                \
        if (vhttp_CONN_IS_PROBED(label, _conn)) {                                                                                    \
            vhttp_##label(_conn->id, __VA_ARGS__);                                                                                   \
        }                                                                                                                          \
    } while (0)

#define vhttp_PROBE_REQUEST0(label, req)                                                                                             \
    do {                                                                                                                           \
        vhttp_req_t *_req = (req);                                                                                                   \
        vhttp_conn_t *_conn = _req->conn;                                                                                            \
        if (vhttp_CONN_IS_PROBED(label, _conn)) {                                                                                    \
            uint64_t _req_id = _conn->callbacks->get_req_id(_req);                                                                 \
            vhttp_##label(_conn->id, _req_id);                                                                                       \
        }                                                                                                                          \
    } while (0)

#define vhttp_PROBE_REQUEST(label, req, ...)                                                                                         \
    do {                                                                                                                           \
        vhttp_req_t *_req = (req);                                                                                                   \
        vhttp_conn_t *_conn = _req->conn;                                                                                            \
        if (vhttp_CONN_IS_PROBED(label, _conn)) {                                                                                    \
            uint64_t _req_id = _conn->callbacks->get_req_id(_req);                                                                 \
            vhttp_##label(_conn->id, _req_id, __VA_ARGS__);                                                                          \
        }                                                                                                                          \
    } while (0)

#define vhttp_PROBE(label, ...)                                                                                                      \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(vhttp_##label##_ENABLED())) {                                                                              \
            vhttp_##label(__VA_ARGS__);                                                                                              \
        }                                                                                                                          \
    } while (0)

#define vhttp_PROBE_HEXDUMP(s, l)                                                                                                    \
    ({                                                                                                                             \
        size_t _l = (l);                                                                                                           \
        ptls_hexdump(alloca(_l * 2 + 1), (s), _l);                                                                                 \
    })

#else

#define vhttp_CONN_IS_PROBED(label, conn) (0)
#define vhttp_PROBE_CONN0(label, conn)
#define vhttp_PROBE_CONN(label, conn, ...)
#define vhttp_PROBE_REQUEST0(label, req)
#define vhttp_PROBE_REQUEST(label, req, ...)
#define vhttp_PROBE(label, ...)
#define vhttp_PROBE_HEXDUMP(s, l)

#endif

/* Helper functions for probing; the functions are defined as non-inlineable, as bcc cannot handle relative offset against a static
 * const (e.g., vhttp_TOKEN_PATH->buf.base). They are available only when vhttp.h is included, so that files under lib/common can
 * include this function without creating dependency against lib/core (e.g., `vhttp_req_t`). */
#ifdef vhttp_h

__attribute__((noinline)) static void vhttp_probe_request_header(vhttp_req_t *req, uint64_t req_index, vhttp_iovec_t name,
                                                               vhttp_iovec_t value)
{
    vhttp_PROBE_CONN(RECEIVE_REQUEST_HEADER, req->conn, req_index, name.base, name.len, value.base, value.len);
    vhttp_LOG_CONN(receive_request_header, req->conn, {
        PTLS_LOG_ELEMENT_UNSIGNED(req_id, req_index);
        PTLS_LOG_APPDATA_ELEMENT_UNSAFESTR(name, name.base, name.len);
        PTLS_LOG_APPDATA_ELEMENT_UNSAFESTR(value, value.base, value.len);
    });
}

__attribute__((noinline)) static void vhttp_probe_response_header(vhttp_req_t *req, uint64_t req_index, vhttp_iovec_t name,
                                                                vhttp_iovec_t value)
{
    vhttp_PROBE_CONN(SEND_RESPONSE_HEADER, req->conn, req_index, name.base, name.len, value.base, value.len);
    vhttp_LOG_CONN(send_response_header, req->conn, {
        PTLS_LOG_ELEMENT_UNSIGNED(req_id, req_index);
        PTLS_LOG_APPDATA_ELEMENT_UNSAFESTR(name, name.base, name.len);
        PTLS_LOG_APPDATA_ELEMENT_UNSAFESTR(value, value.base, value.len);
    });
}

static inline void vhttp_probe_log_request(vhttp_req_t *req, uint64_t req_index)
{
    vhttp_PROBE_CONN(RECEIVE_REQUEST, req->conn, req_index, req->version);
    vhttp_LOG_CONN(receive_request, req->conn, {
        PTLS_LOG_ELEMENT_UNSIGNED(req_id, req_index);
        PTLS_LOG_ELEMENT_SIGNED(http_version, req->version);
    });
    if (vhttp_CONN_IS_PROBED(RECEIVE_REQUEST_HEADER, req->conn) || ptls_log.is_active) {
        if (req->input.authority.base != NULL)
            vhttp_probe_request_header(req, req_index, vhttp_TOKEN_AUTHORITY->buf, req->input.authority);
        if (req->input.method.base != NULL)
            vhttp_probe_request_header(req, req_index, vhttp_TOKEN_METHOD->buf, req->input.method);
        if (req->input.path.base != NULL)
            vhttp_probe_request_header(req, req_index, vhttp_TOKEN_PATH->buf, req->input.path);
        if (req->input.scheme != NULL)
            vhttp_probe_request_header(req, req_index, vhttp_TOKEN_SCHEME->buf, req->input.scheme->name);
        size_t i;
        for (i = 0; i != req->headers.size; ++i) {
            vhttp_header_t *h = req->headers.entries + i;
            vhttp_probe_request_header(req, req_index, *h->name, h->value);
        }
    }
}

static inline void vhttp_probe_log_response(vhttp_req_t *req, uint64_t req_index)
{
    vhttp_PROBE_CONN(SEND_RESPONSE, req->conn, req_index, req->res.status);
    vhttp_LOG_CONN(send_response, req->conn, {
        PTLS_LOG_ELEMENT_UNSIGNED(req_id, req_index);
        PTLS_LOG_ELEMENT_SIGNED(status, req->res.status);
    });
    if (vhttp_CONN_IS_PROBED(SEND_RESPONSE_HEADER, req->conn) || ptls_log.is_active) {
        if (req->res.content_length != SIZE_MAX) {
            char buf[sizeof(vhttp_SIZE_T_LONGEST_STR)];
            size_t len = (size_t)sprintf(buf, "%zu", req->res.content_length);
            vhttp_probe_response_header(req, req_index, vhttp_TOKEN_CONTENT_LENGTH->buf, vhttp_iovec_init(buf, len));
        }
        size_t i;
        for (i = 0; i != req->res.headers.size; ++i) {
            vhttp_header_t *h = req->res.headers.entries + i;
            vhttp_probe_response_header(req, req_index, *h->name, h->value);
        }
    }
}

#endif

#endif
