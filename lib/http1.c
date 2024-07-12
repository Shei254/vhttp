/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Shota Fukumori,
 *                         Fastly, Inc.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "picohttpparser.h"
#include "vhttp.h"
#include "vhttp/http1.h"
#include "vhttp/http2.h"
#include "./probes_.h"

enum enum_vhttp_http1_ostream_state {
    OSTREAM_STATE_HEAD,
    OSTREAM_STATE_BODY,
    OSTREAM_STATE_DONE,
};

struct st_vhttp_http1_finalostream_t {
    vhttp_ostream_t super;
    enum enum_vhttp_http1_ostream_state state;
    char *chunked_buf; /* buffer used for chunked-encoding (NULL unless chunked encoding is used) */
    struct {
        /**
         * if `vhttp_socket_write` is currently writing an informational response
         */
        unsigned write_inflight : 1;
        /**
         * buffer used to store informational responses to be sent, when write of an informational response is inflight
         */
        vhttp_iovec_vector_t pending;
        /**
         * buffer used to delay the execution of `finalostream_send`, when write of an informational respnose is inflight;
         * availability is indicated by `inbufs != NULL`
         */
        struct {
            vhttp_sendvec_t *inbufs;
            size_t inbufcnt;
            vhttp_send_state_t send_state;
        } pending_final;
    } informational;
};

struct st_vhttp_http1_conn_t {
    vhttp_conn_t super;
    vhttp_socket_t *sock;
    vhttp_timer_t _timeout_entry;
    vhttp_timer_t _io_timeout_entry;
    uint64_t _req_index;
    size_t _prevreqlen;
    size_t _unconsumed_request_size;
    struct st_vhttp_http1_req_entity_reader *_req_entity_reader;
    struct st_vhttp_http1_finalostream_t _ostr_final;
    struct {
        void *data;
        vhttp_http1_upgrade_cb cb;
    } upgrade;
    /**
     * the request body buffer
     */
    vhttp_buffer_t *req_body;
    /**
     * the HTTP request / response (intentionally placed at the last, since it is a large structure and has it's own ctor)
     */
    vhttp_req_t req;
};

struct st_vhttp_http1_req_entity_reader {
    void (*handle_incoming_entity)(struct st_vhttp_http1_conn_t *conn);
};

struct st_vhttp_http1_content_length_entity_reader {
    struct st_vhttp_http1_req_entity_reader super;
    size_t content_length;
};

struct st_vhttp_http1_chunked_entity_reader {
    struct st_vhttp_http1_req_entity_reader super;
    struct phr_chunked_decoder decoder;
};

static void finalostream_send(vhttp_ostream_t *_self, vhttp_req_t *req, vhttp_sendvec_t *inbufs, size_t inbufcnt, vhttp_send_state_t state);
static void finalostream_send_informational(vhttp_ostream_t *_self, vhttp_req_t *req);
static void reqread_on_read(vhttp_socket_t *sock, const char *err);
static void reqread_on_timeout(vhttp_timer_t *entry);
static void req_io_on_timeout(vhttp_timer_t *entry);
static void reqread_start(struct st_vhttp_http1_conn_t *conn);
static int foreach_request(vhttp_conn_t *_conn, int (*cb)(vhttp_req_t *req, void *cbdata), void *cbdata);

static void init_request(struct st_vhttp_http1_conn_t *conn)
{
    if (conn->_req_index != 0) {
        if (conn->req_body != NULL)
            vhttp_buffer_dispose(&conn->req_body);
        vhttp_dispose_request(&conn->req);
        if (conn->_unconsumed_request_size)
            vhttp_buffer_consume(&conn->sock->input, conn->_unconsumed_request_size);
    }
    assert(conn->req_body == NULL);
    vhttp_init_request(&conn->req, &conn->super, NULL);

    ++conn->_req_index;
    conn->req._ostr_top = &conn->_ostr_final.super;

    conn->_ostr_final = (struct st_vhttp_http1_finalostream_t){{
        NULL,              /* next */
        finalostream_send, /* do_send */
        NULL,              /* stop */
        conn->super.ctx->globalconf->send_informational_mode == vhttp_SEND_INFORMATIONAL_MODE_ALL ? finalostream_send_informational
                                                                                                : NULL, /* send_informational */
    }};
}

static void close_connection(struct st_vhttp_http1_conn_t *conn, int close_socket)
{
    if (conn->sock != NULL)
        vhttp_PROBE_CONN0(H1_CLOSE, &conn->super);
    vhttp_timer_unlink(&conn->_timeout_entry);
    vhttp_timer_unlink(&conn->_io_timeout_entry);
    if (conn->req_body != NULL)
        vhttp_buffer_dispose(&conn->req_body);
    vhttp_dispose_request(&conn->req);
    if (conn->sock != NULL && close_socket)
        vhttp_socket_close(conn->sock);
    vhttp_destroy_connection(&conn->super);
}

static void cleanup_connection(struct st_vhttp_http1_conn_t *conn)
{
    if (!conn->req.http1_is_persistent) {
        /* TODO use lingering close */
        close_connection(conn, 1);
        return;
    }

    assert(conn->req.proceed_req == NULL);
    assert(conn->_req_entity_reader == NULL);

    /* handle next request */
    init_request(conn);
    conn->req.write_req.cb = NULL;
    conn->req.write_req.ctx = NULL;
    conn->req.proceed_req = NULL;
    conn->_prevreqlen = 0;
    conn->_unconsumed_request_size = 0;

    if (conn->sock->input->size == 0)
        vhttp_conn_set_state(&conn->super, vhttp_CONN_STATE_IDLE);

    reqread_start(conn);
}

/**
 * timer is activated if cb != NULL, disactivated otherwise
 */
static void set_req_timeout(struct st_vhttp_http1_conn_t *conn, uint64_t timeout, vhttp_timer_cb cb)
{
    if (conn->req.is_tunnel_req)
        cb = NULL;
    if (conn->_timeout_entry.cb != NULL)
        vhttp_timer_unlink(&conn->_timeout_entry);
    conn->_timeout_entry.cb = cb;
    if (cb != NULL)
        vhttp_timer_link(conn->super.ctx->loop, timeout, &conn->_timeout_entry);
}

static void set_req_io_timeout(struct st_vhttp_http1_conn_t *conn, uint64_t timeout, vhttp_timer_cb cb)
{
    if (conn->req.is_tunnel_req)
        cb = NULL;
    if (conn->_io_timeout_entry.cb != NULL)
        vhttp_timer_unlink(&conn->_io_timeout_entry);
    conn->_io_timeout_entry.cb = cb;
    if (cb != NULL)
        vhttp_timer_link(conn->super.ctx->loop, timeout, &conn->_io_timeout_entry);
}

static void clear_timeouts(struct st_vhttp_http1_conn_t *conn)
{
    set_req_timeout(conn, 0, NULL);
    set_req_io_timeout(conn, 0, NULL);
}

static void entity_read_do_send_error(struct st_vhttp_http1_conn_t *conn, int status, size_t status_error_index, const char *reason,
                                      const char *body)
{
    conn->req.proceed_req = NULL;
    conn->_req_entity_reader = NULL;
    clear_timeouts(conn);
    vhttp_socket_read_stop(conn->sock);
    /* FIXME We should check if `vhttp_proceed_request` has been called, rather than trying to guess if we have (I'm unsure if the
     * contract is for vhttp_req_t::_generator to become non-NULL immediately after `vhttp_proceed_request` is being called). */
    if (conn->req._generator == NULL && conn->_ostr_final.state == OSTREAM_STATE_HEAD) {
        conn->super.ctx->emitted_error_status[status_error_index]++;
        vhttp_send_error_generic(&conn->req, status, reason, body, vhttp_SEND_ERROR_HTTP1_CLOSE_CONNECTION);
    } else {
        conn->req.http1_is_persistent = 0;
        if (conn->_ostr_final.state == OSTREAM_STATE_DONE)
            cleanup_connection(conn);
    }
}

#define DECL_ENTITY_READ_SEND_ERROR_XXX(status_)                                                                                   \
    static void entity_read_send_error_##status_(struct st_vhttp_http1_conn_t *conn, const char *reason, const char *body)           \
    {                                                                                                                              \
        entity_read_do_send_error(conn, status_, vhttp_STATUS_ERROR_##status_, reason, body);                                        \
    }

DECL_ENTITY_READ_SEND_ERROR_XXX(400)
DECL_ENTITY_READ_SEND_ERROR_XXX(413)
DECL_ENTITY_READ_SEND_ERROR_XXX(502)

static void handle_one_body_fragment(struct st_vhttp_http1_conn_t *conn, size_t fragment_size, size_t extra_bytes, int complete)
{
    if (fragment_size == 0 && !complete) {
        vhttp_buffer_consume(&conn->sock->input, extra_bytes);
        return;
    }

    clear_timeouts(conn);
    vhttp_socket_read_stop(conn->sock);

    /* move data being read to req_body */
    if (!vhttp_buffer_try_append(&conn->req_body, conn->sock->input->bytes, fragment_size)) {
        entity_read_send_error_502(conn, "Bad Gateway", "Bad Gateway");
        return;
    }
    vhttp_buffer_consume(&conn->sock->input, fragment_size + extra_bytes);
    conn->req.req_body_bytes_received += fragment_size;

    /* invoke action */
    conn->req.entity = vhttp_iovec_init(conn->req_body->bytes, conn->req_body->size);
    if (conn->req.write_req.cb(conn->req.write_req.ctx, complete) != 0) {
        entity_read_send_error_502(conn, "Bad Gateway", "Bad Gateway");
        return;
    }
    if (complete) {
        conn->req.proceed_req = NULL;
        conn->_req_entity_reader = NULL;
        if (conn->_ostr_final.state == OSTREAM_STATE_DONE) {
            cleanup_connection(conn);
        }
    }
}

static void handle_chunked_entity_read(struct st_vhttp_http1_conn_t *conn)
{
    struct st_vhttp_http1_chunked_entity_reader *reader = (void *)conn->_req_entity_reader;
    size_t bufsz;
    ssize_t ret;

    /* decode the incoming data */
    if ((bufsz = conn->sock->input->size) == 0)
        return;
    ret = phr_decode_chunked(&reader->decoder, conn->sock->input->bytes, &bufsz);
    if (ret != -1 && bufsz + conn->req.req_body_bytes_received >= conn->super.ctx->globalconf->max_request_entity_size) {
        entity_read_send_error_413(conn, "Request Entity Too Large", "request entity is too large");
        return;
    }
    if (ret < 0) {
        if (ret == -2) {
            /* incomplete */
            handle_one_body_fragment(conn, bufsz, conn->sock->input->size - bufsz, 0);
        } else {
            /* error */
            entity_read_send_error_400(conn, "Invalid Request", "broken chunked-encoding");
        }
    } else {
        /* complete */
        assert(bufsz + ret <= conn->sock->input->size);
        conn->sock->input->size = bufsz + ret;
        handle_one_body_fragment(conn, bufsz, 0, 1);
    }
}

static int create_chunked_entity_reader(struct st_vhttp_http1_conn_t *conn)
{
    struct st_vhttp_http1_chunked_entity_reader *reader = vhttp_mem_alloc_pool(&conn->req.pool, *reader, 1);
    conn->_req_entity_reader = &reader->super;

    reader->super.handle_incoming_entity = handle_chunked_entity_read;
    memset(&reader->decoder, 0, sizeof(reader->decoder));
    reader->decoder.consume_trailer = 1;

    return 0;
}

static void handle_content_length_entity_read(struct st_vhttp_http1_conn_t *conn)
{
    int complete = 0;
    struct st_vhttp_http1_content_length_entity_reader *reader = (void *)conn->_req_entity_reader;
    size_t length = conn->sock->input->size;

    if (conn->req.req_body_bytes_received + conn->sock->input->size >= reader->content_length) {
        complete = 1;
        length = reader->content_length - conn->req.req_body_bytes_received;
    }
    if (!complete && length == 0)
        return;

    handle_one_body_fragment(conn, length, 0, complete);
}

static int create_content_length_entity_reader(struct st_vhttp_http1_conn_t *conn, size_t content_length)
{
    struct st_vhttp_http1_content_length_entity_reader *reader = vhttp_mem_alloc_pool(&conn->req.pool, *reader, 1);
    conn->_req_entity_reader = &reader->super;

    reader->super.handle_incoming_entity = handle_content_length_entity_read;
    reader->content_length = content_length;

    return 0;
}

static int create_entity_reader(struct st_vhttp_http1_conn_t *conn, const struct phr_header *entity_header)
{
    /* strlen("content-length") is unequal to sizeof("transfer-encoding"), and thus checking the length only is sufficient */
    if (entity_header->name_len == sizeof("transfer-encoding") - 1) {
        /* transfer-encoding */
        if (!vhttp_lcstris(entity_header->value, entity_header->value_len, vhttp_STRLIT("chunked"))) {
            entity_read_send_error_400(conn, "Invalid Request", "unknown transfer-encoding");
            return -1;
        }
        return create_chunked_entity_reader(conn);
    } else {
        /* content-length */
        size_t content_length = vhttp_strtosize(entity_header->value, entity_header->value_len);
        if (content_length == SIZE_MAX) {
            entity_read_send_error_400(conn, "Invalid Request", "broken content-length header");
            return -1;
        }
        if (content_length > conn->super.ctx->globalconf->max_request_entity_size) {
            entity_read_send_error_413(conn, "Request Entity Too Large", "request entity is too large");
            return -1;
        }
        conn->req.content_length = content_length;
        return create_content_length_entity_reader(conn, (size_t)content_length);
    }
    /* failed */
    return -1;
}

static const char *init_headers(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, const struct phr_header *src, size_t len,
                                vhttp_iovec_t *connection, vhttp_iovec_t *host, vhttp_iovec_t *upgrade, vhttp_iovec_t *expect,
                                ssize_t *entity_header_index)
{
    *entity_header_index = -1;

    assert(headers->size == 0);

    /* setup */
    if (len != 0) {
        size_t i;
        vhttp_vector_reserve(pool, headers, len);
        for (i = 0; i != len; ++i) {
            const vhttp_token_t *name_token;
            /* reject multiline header */
            if (src[i].name_len == 0)
                return "line folding of header fields is not supported";
            char orig_case[src[i].name_len];
            /* preserve the original case */
            memcpy(orig_case, src[i].name, src[i].name_len);
            /* convert to lower-case in-place */
            vhttp_strtolower((char *)src[i].name, src[i].name_len);
            if ((name_token = vhttp_lookup_token(src[i].name, src[i].name_len)) != NULL) {
                if (name_token->flags.is_init_header_special) {
                    if (name_token == vhttp_TOKEN_HOST) {
                        host->base = (char *)src[i].value;
                        host->len = src[i].value_len;
                    } else if (name_token == vhttp_TOKEN_CONTENT_LENGTH) {
                        if (*entity_header_index == -1)
                            *entity_header_index = i;
                    } else if (name_token == vhttp_TOKEN_TRANSFER_ENCODING) {
                        *entity_header_index = i;
                    } else if (name_token == vhttp_TOKEN_EXPECT) {
                        expect->base = (char *)src[i].value;
                        expect->len = src[i].value_len;
                    } else if (name_token == vhttp_TOKEN_UPGRADE) {
                        upgrade->base = (char *)src[i].value;
                        upgrade->len = src[i].value_len;
                    } else {
                        assert(!"logic flaw");
                    }
                } else {
                    vhttp_add_header(pool, headers, name_token, orig_case, src[i].value, src[i].value_len);
                    if (name_token == vhttp_TOKEN_CONNECTION)
                        *connection = headers->entries[headers->size - 1].value;
                }
            } else {
                vhttp_add_header_by_str(pool, headers, src[i].name, src[i].name_len, 0, orig_case, src[i].value, src[i].value_len);
            }
        }
    }

    return NULL;
}

static int upgrade_is_h2(vhttp_iovec_t upgrade)
{
    if (vhttp_lcstris(upgrade.base, upgrade.len, vhttp_STRLIT("h2c")) || vhttp_lcstris(upgrade.base, upgrade.len, vhttp_STRLIT("h2c-14")) ||
        vhttp_lcstris(upgrade.base, upgrade.len, vhttp_STRLIT("h2c-16")))
        return 1;
    return 0;
}

static const char fixup_request_is_h2_upgrade[] = "fixup h2 upgrade";

static const char *fixup_request(struct st_vhttp_http1_conn_t *conn, struct phr_header *headers, size_t num_headers,
                                 int minor_version, vhttp_iovec_t *expect, ssize_t *entity_header_index)
{
    vhttp_iovec_t connection = {NULL, 0}, host = {NULL, 0}, upgrade = {NULL, 0};
    enum { METHOD_NORMAL, METHOD_CONNECT, METHOD_CONNECT_UDP } method_type;
    const char *ret;

    expect->base = NULL;
    expect->len = 0;

    conn->req.input.scheme = conn->sock->ssl != NULL ? &vhttp_URL_SCHEME_HTTPS : &vhttp_URL_SCHEME_HTTP;
    conn->req.version = 0x100 | (minor_version != 0);

    /* RFC 7231 6.2: a server MUST NOT send a 1xx response to an HTTP/1.0 client */
    if (conn->req.version < 0x101)
        conn->_ostr_final.super.send_informational = NULL;

    if (vhttp_memis(conn->req.input.method.base, conn->req.input.method.len, vhttp_STRLIT("CONNECT"))) {
        method_type = METHOD_CONNECT;
    } else if (vhttp_memis(conn->req.input.method.base, conn->req.input.method.len, vhttp_STRLIT("CONNECT-UDP"))) {
        method_type = METHOD_CONNECT_UDP;
    } else {
        method_type = METHOD_NORMAL;
    }

    /* init headers */
    if ((ret = init_headers(&conn->req.pool, &conn->req.headers, headers, num_headers, &connection, &host, &upgrade, expect,
                            entity_header_index)) != NULL)
        return ret;

    /* copy the values to pool, since the buffer pointed by the headers may get realloced */
    if (*entity_header_index != -1 || method_type != METHOD_NORMAL || upgrade.base != NULL) {
        size_t i;
        conn->req.input.method = vhttp_strdup(&conn->req.pool, conn->req.input.method.base, conn->req.input.method.len);
        conn->req.input.path = vhttp_strdup(&conn->req.pool, conn->req.input.path.base, conn->req.input.path.len);
        for (i = 0; i != conn->req.headers.size; ++i) {
            vhttp_header_t *header = conn->req.headers.entries + i;
            if (!vhttp_iovec_is_token(header->name)) {
                *header->name = vhttp_strdup(&conn->req.pool, header->name->base, header->name->len);
            }
            header->value = vhttp_strdup(&conn->req.pool, header->value.base, header->value.len);
        }
        if (host.base != NULL)
            host = vhttp_strdup(&conn->req.pool, host.base, host.len);
        if (upgrade.base != NULL)
            upgrade = vhttp_strdup(&conn->req.pool, upgrade.base, upgrade.len);
    }

    if (method_type == METHOD_CONNECT) {
        /* CONNECT method, validate, setting the target host in `req->input.authority`. Path becomes empty. */
        if (conn->req.version < 0x101 || conn->req.input.path.len == 0 ||
            (host.base != NULL && !vhttp_memis(conn->req.input.path.base, conn->req.input.path.len, host.base, host.len)) ||
            *entity_header_index != -1)
            return "invalid request";
        conn->req.input.authority = conn->req.input.path;
        conn->req.input.path = vhttp_iovec_init(NULL, 0);
        conn->req.is_tunnel_req = 1;
    } else {
        /* request line is in ordinary form, path might contain absolute URL; if so, convert it */
        if (conn->req.input.path.len != 0 && conn->req.input.path.base[0] != '/') {
            vhttp_url_t url;
            if (vhttp_url_parse(&conn->req.pool, conn->req.input.path.base, conn->req.input.path.len, &url) == 0) {
                conn->req.input.scheme = url.scheme;
                conn->req.input.path = url.path;
                host = url.authority; /* authority part of the absolute form overrides the host header field (RFC 7230 S5.4) */
            }
        }
        /* move host header to req->authority */
        if (host.base != NULL)
            conn->req.input.authority = host;
        /* each protocol implementation validates masque */
        if (!vhttp_req_validate_pseudo_headers(&conn->req))
            return "invalid request";
        /* special handling for CONNECT-UDP, else it is an ordinary request */
        if (method_type == METHOD_CONNECT_UDP) {
            conn->req.is_tunnel_req = 1;
        } else {
            /* handle Connection and Upgrade header fields */
            if (connection.base != NULL) {
                /* TODO contains_token function can be faster */
                if (vhttp_contains_token(connection.base, connection.len, vhttp_STRLIT("keep-alive"), ',')) {
                    conn->req.http1_is_persistent = 1;
                }
                /* Upgrade is respected only for requests without bodies. Use of upgrade on a request with body is unsupported,
                 * because we reuse the entity reader for reading the body and the tunnelled data. */
                if (upgrade.base != NULL && vhttp_contains_token(connection.base, connection.len, vhttp_STRLIT("upgrade"), ',') &&
                    *entity_header_index == -1) {
                    /* early return if upgrading to h2 */
                    if (upgrade_is_h2(upgrade) && conn->sock->ssl == NULL && conn->super.ctx->globalconf->http1.upgrade_to_http2)
                        return fixup_request_is_h2_upgrade;
                    conn->req.upgrade = upgrade;
                    conn->req.is_tunnel_req = 1;
                    conn->req.http1_is_persistent = 0;
                }
            } else if (conn->req.version >= 0x101) {
                /* defaults to keep-alive if >= HTTP/1.1 */
                conn->req.http1_is_persistent = 1;
            }
            /* disable keep-alive if shutdown is requested */
            if (conn->req.http1_is_persistent && conn->super.ctx->shutdown_requested)
                conn->req.http1_is_persistent = 0;
        }
    }

    return NULL;
}

static void on_continue_sent(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http1_conn_t *conn = sock->data;

    if (err != NULL) {
        close_connection(conn, 1);
        return;
    }

    vhttp_socket_read_start(sock, reqread_on_read);
    conn->_req_entity_reader->handle_incoming_entity(conn);
}

static int contains_crlf_only(const char *s, size_t len)
{
    for (; len != 0; ++s, --len)
        if (!(*s == '\r' || *s == '\n'))
            return 0;
    return 1;
}

static void send_bad_request(struct st_vhttp_http1_conn_t *conn, const char *body)
{
    vhttp_socket_read_stop(conn->sock);
    vhttp_send_error_400(&conn->req, "Bad Request", body, vhttp_SEND_ERROR_BROKEN_REQUEST | vhttp_SEND_ERROR_HTTP1_CLOSE_CONNECTION);
}

static void resume_request_read(struct st_vhttp_http1_conn_t *conn)
{
    set_req_timeout(conn, conn->super.ctx->globalconf->http1.req_timeout, reqread_on_timeout);
    set_req_io_timeout(conn, conn->super.ctx->globalconf->http1.req_io_timeout, req_io_on_timeout);
    vhttp_socket_read_start(conn->sock, reqread_on_read);
}

static void proceed_request(vhttp_req_t *req, const char *errstr)
{
    struct st_vhttp_http1_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http1_conn_t, req, req);

    if (errstr != NULL) {
        entity_read_send_error_502(conn, "Bad Gateway", "Bad Gateway");
        return;
    }

    assert(conn->req.entity.len == conn->req_body->size);
    vhttp_buffer_consume(&conn->req_body, conn->req_body->size);

    resume_request_read(conn);
}

static int write_req_non_streaming(void *_req, int is_end_stream)
{
    struct st_vhttp_http1_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http1_conn_t, req, _req);

    if (is_end_stream) {
        conn->req.proceed_req = NULL;
        vhttp_process_request(&conn->req);
    } else {
        resume_request_read(conn);
    }
    return 0;
}

static int write_req_first(void *_req, int is_end_stream)
{
    struct st_vhttp_http1_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http1_conn_t, req, _req);

    /* if possible, switch to streaming request body mode */
    if (!is_end_stream && vhttp_req_can_stream_request(&conn->req)) {
        conn->req.write_req.cb = NULL; /* will be set to something before `proceed_req` is being invoked */
        conn->req.proceed_req = proceed_request;
        vhttp_process_request(&conn->req);
        return 0;
    }

    conn->req.write_req.cb = write_req_non_streaming;
    return write_req_non_streaming(&conn->req, is_end_stream);
}

static int write_req_connect_first(void *_req, int is_end_stream)
{
    struct st_vhttp_http1_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http1_conn_t, req, _req);

    conn->req.write_req.cb = NULL; /* will not be called again until proceed_req is called by the generator */
    if (is_end_stream)
        conn->req.proceed_req = NULL;

    return 0;
}

static void handle_incoming_request(struct st_vhttp_http1_conn_t *conn)
{
    size_t inreqlen = conn->sock->input->size < vhttp_MAX_REQLEN ? conn->sock->input->size : vhttp_MAX_REQLEN;
    int reqlen, minor_version;
    struct phr_header headers[vhttp_MAX_HEADERS];
    size_t num_headers = vhttp_MAX_HEADERS;
    ssize_t entity_body_header_index;
    vhttp_iovec_t expect;

    if (conn->sock->input->size != 0)
        vhttp_conn_set_state(&conn->super, vhttp_CONN_STATE_ACTIVE);

    /* need to set request_begin_at here for keep-alive connection */
    if (vhttp_timeval_is_null(&conn->req.timestamps.request_begin_at))
        conn->req.timestamps.request_begin_at = vhttp_gettimeofday(conn->super.ctx->loop);

    reqlen = phr_parse_request(conn->sock->input->bytes, inreqlen, (const char **)&conn->req.input.method.base,
                               &conn->req.input.method.len, (const char **)&conn->req.input.path.base, &conn->req.input.path.len,
                               &minor_version, headers, &num_headers, conn->_prevreqlen);
    conn->_prevreqlen = inreqlen;

    switch (reqlen) {
    default: { // parse complete
        conn->_unconsumed_request_size = reqlen;
        const char *err;
        if ((err = fixup_request(conn, headers, num_headers, minor_version, &expect, &entity_body_header_index)) != NULL &&
            err != fixup_request_is_h2_upgrade) {
            clear_timeouts(conn);
            send_bad_request(conn, err);
            return;
        }
        vhttp_probe_log_request(&conn->req, conn->_req_index);
        if (err == fixup_request_is_h2_upgrade) {
            clear_timeouts(conn);
            vhttp_socket_read_stop(conn->sock);
            if (vhttp_http2_handle_upgrade(&conn->req, conn->super.connected_at) != 0)
                vhttp_send_error_400(&conn->req, "Invalid Request", "Broken upgrade request to HTTP/2", 0);
        } else if (entity_body_header_index != -1) {
            /* Request has body, start reading it. Invocation of `vhttp_process_request` is delayed to reduce backend concurrency. */
            conn->req.timestamps.request_body_begin_at = vhttp_gettimeofday(conn->super.ctx->loop);
            if (expect.base != NULL) {
                if (!vhttp_lcstris(expect.base, expect.len, vhttp_STRLIT("100-continue"))) {
                    clear_timeouts(conn);
                    vhttp_socket_read_stop(conn->sock);
                    vhttp_send_error_417(&conn->req, "Expectation Failed", "unknown expectation",
                                       vhttp_SEND_ERROR_HTTP1_CLOSE_CONNECTION);
                    return;
                }
            }
            if (create_entity_reader(conn, headers + entity_body_header_index) != 0)
                return;
            conn->req.write_req.cb = write_req_first;
            conn->req.write_req.ctx = &conn->req;
            conn->_unconsumed_request_size = 0;
            vhttp_buffer_consume(&conn->sock->input, reqlen);
            vhttp_buffer_init(&conn->req_body, &vhttp_socket_buffer_prototype);
            if (expect.base != NULL) {
                static const vhttp_iovec_t res = {vhttp_STRLIT("HTTP/1.1 100 Continue\r\n\r\n")};
                vhttp_socket_write(conn->sock, (void *)&res, 1, on_continue_sent);
                /* processing of the incoming entity is postponed until the 100 response is sent */
                vhttp_socket_read_stop(conn->sock);
                return;
            }
            conn->_req_entity_reader->handle_incoming_entity(conn);
        } else if (conn->req.is_tunnel_req) {
            /* Is a CONNECT request or an upgrade (e.g., WebSocket). Request is submitted immediately and body is streamed. */
            if (!vhttp_req_can_stream_request(&conn->req) &&
                vhttp_memis(conn->req.input.method.base, conn->req.input.method.len, vhttp_STRLIT("CONNECT"))) {
                vhttp_send_error_405(&conn->req, "Method Not Allowed", "Method Not Allowed", 0);
                return;
            }
            if (create_content_length_entity_reader(conn, SIZE_MAX) != 0)
                return;
            conn->_unconsumed_request_size = 0;
            vhttp_buffer_consume(&conn->sock->input, reqlen);
            vhttp_buffer_init(&conn->req_body, &vhttp_socket_buffer_prototype);
            conn->req.write_req.cb = write_req_connect_first;
            conn->req.write_req.ctx = &conn->req;
            conn->req.proceed_req = proceed_request;
            conn->_req_entity_reader->handle_incoming_entity(conn); /* read payload received early before submitting the request */
            if (conn->req.entity.base == NULL)
                conn->req.entity = vhttp_iovec_init("", 0); /* if nothing was read, still indicate that body exists */
            /* stop reading (this might or might not be done by `handle_incoming_entity`) until HTTP response is given */
            vhttp_socket_read_stop(conn->sock);
            clear_timeouts(conn);
            vhttp_process_request(&conn->req);
        } else {
            /* Ordinary request without request body. */
            clear_timeouts(conn);
            vhttp_socket_read_stop(conn->sock);
            vhttp_process_request(&conn->req);
        }
    }
        return;
    case -2: // incomplete
        if (inreqlen == vhttp_MAX_REQLEN) {
            send_bad_request(conn, "Bad Request");
        }
        return;
    case -1: // error
        /* upgrade to HTTP/2 if the request starts with: PRI * HTTP/2 */
        if (conn->super.ctx->globalconf->http1.upgrade_to_http2) {
            /* should check up to the first octet that phr_parse_request returns an error */
            static const vhttp_iovec_t HTTP2_SIG = {vhttp_STRLIT("PRI * HTTP/2")};
            if (conn->sock->input->size >= HTTP2_SIG.len && memcmp(conn->sock->input->bytes, HTTP2_SIG.base, HTTP2_SIG.len) == 0) {
                vhttp_accept_ctx_t accept_ctx = {conn->super.ctx, conn->super.hosts};
                vhttp_socket_t *sock = conn->sock;
                struct timeval connected_at = conn->super.connected_at;
                /* destruct the connection after detatching the socket */
                conn->sock = NULL;
                close_connection(conn, 1);
                /* and accept as http2 connection */
                vhttp_http2_accept(&accept_ctx, sock, connected_at);
                return;
            }
        }
        if (inreqlen <= 4 && contains_crlf_only(conn->sock->input->bytes, inreqlen)) {
            close_connection(conn, 1);
        } else {
            send_bad_request(conn, "Bad Request");
        }
        return;
    }
}

void reqread_on_read(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http1_conn_t *conn = sock->data;

    if (err != NULL) {
        close_connection(conn, 1);
        return;
    }

    set_req_io_timeout(conn, conn->super.ctx->globalconf->http1.req_io_timeout, req_io_on_timeout);
    if (conn->_req_entity_reader == NULL)
        handle_incoming_request(conn);
    else
        conn->_req_entity_reader->handle_incoming_entity(conn);
}

static void close_idle_connection(vhttp_conn_t *_conn)
{
    struct st_vhttp_http1_conn_t *conn = (void *)_conn;
    conn->req.http1_is_persistent = 0;
    close_connection(conn, 1);
}

static void on_timeout(struct st_vhttp_http1_conn_t *conn)
{
    if (conn->_req_index == 1) {
        /* assign hostconf and bind conf so that the request can be logged */
        vhttp_hostconf_t *hostconf = vhttp_req_setup(&conn->req);
        vhttp_req_bind_conf(&conn->req, hostconf, &hostconf->fallback_path);
        /* set error status for logging */
        conn->req.res.reason = "Request Timeout";
    }

    close_idle_connection(&conn->super);
}

static void req_io_on_timeout(vhttp_timer_t *entry)
{
    struct st_vhttp_http1_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http1_conn_t, _io_timeout_entry, entry);
    conn->super.ctx->http1.events.request_io_timeouts++;
    on_timeout(conn);
}

static void reqread_on_timeout(vhttp_timer_t *entry)
{
    struct st_vhttp_http1_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http1_conn_t, _timeout_entry, entry);
    conn->super.ctx->http1.events.request_timeouts++;
    on_timeout(conn);
}

static inline void reqread_start(struct st_vhttp_http1_conn_t *conn)
{
    set_req_timeout(conn, conn->super.ctx->globalconf->http1.req_timeout, reqread_on_timeout);
    set_req_io_timeout(conn, conn->super.ctx->globalconf->http1.req_io_timeout, req_io_on_timeout);
    vhttp_socket_read_start(conn->sock, reqread_on_read);
    if (conn->sock->input->size != 0)
        handle_incoming_request(conn);
}

static void on_send_next(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http1_conn_t *conn = sock->data;

    if (err != NULL)
        close_connection(conn, 1);
    else
        vhttp_proceed_response(&conn->req);
}

static void on_send_complete_post_trailers(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http1_conn_t *conn = sock->data;

    if (err != NULL)
        conn->req.http1_is_persistent = 0;

    conn->_ostr_final.state = OSTREAM_STATE_DONE;
    if (conn->req.proceed_req == NULL)
        cleanup_connection(conn);
}

static void on_send_complete(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http1_conn_t *conn = sock->data;

    if (err == NULL) {
        if (conn->req._ostr_top != &conn->_ostr_final.super) {
            err = "pull error";
        } else {
            /* success */
            conn->req.timestamps.response_end_at = vhttp_gettimeofday(conn->super.ctx->loop);
        }
    }

    if (err != NULL)
        conn->req.http1_is_persistent = 0;

    if (err == NULL && conn->req.send_server_timing && conn->_ostr_final.chunked_buf != NULL) {
        vhttp_iovec_t trailer;
        if ((trailer = vhttp_build_server_timing_trailer(&conn->req, vhttp_STRLIT("server-timing: "), vhttp_STRLIT("\r\n\r\n"))).len !=
            0) {
            vhttp_socket_write(conn->sock, &trailer, 1, on_send_complete_post_trailers);
            return;
        }
    }

    conn->_ostr_final.state = OSTREAM_STATE_DONE;

    if (conn->req.is_tunnel_req) {
        /* We have received a complete request (the end of the request is the request headers, see `fixup_request`), and the
         * connection is not going to handle any more requests. Therefore, we can close the connection immediately, regardless of if
         * the connection had been turned into a tunnel. */
        assert(!conn->req.http1_is_persistent);
        cleanup_connection(conn);
    } else if (conn->req.proceed_req == NULL) {
        /* Upstream has sent an early response. Continue forwarding the request body. */
        cleanup_connection(conn);
    }
}

static void on_upgrade_complete(vhttp_socket_t *socket, const char *err)
{
    struct st_vhttp_http1_conn_t *conn = socket->data;
    vhttp_http1_upgrade_cb cb = conn->upgrade.cb;
    void *data = conn->upgrade.data;
    vhttp_socket_t *sock = NULL;
    size_t headers_size = 0;

    /* destruct the connection (after detaching the socket) */
    if (err == 0) {
        sock = conn->sock;
        headers_size = conn->_unconsumed_request_size;
        close_connection(conn, 0);
    } else {
        close_connection(conn, 1);
    }

    cb(data, sock, headers_size);
}

static size_t flatten_headers_estimate_size(vhttp_req_t *req, size_t server_name_and_connection_len)
{
    size_t len = sizeof("HTTP/1.1  \r\nserver: \r\nconnection: \r\ncontent-length: \r\n\r\n") + 3 + strlen(req->res.reason) +
                 server_name_and_connection_len + sizeof(vhttp_UINT64_LONGEST_STR) - 1 + sizeof("cache-control: private") - 1;
    const vhttp_header_t *header, *end;

    for (header = req->res.headers.entries, end = header + req->res.headers.size; header != end; ++header)
        len += header->name->len + header->value.len + 4;

    return len;
}

static size_t flatten_res_headers(char *buf, vhttp_req_t *req)
{
    char *dst = buf;
    size_t i;
    for (i = 0; i != req->res.headers.size; ++i) {
        const vhttp_header_t *header = req->res.headers.entries + i;
        memcpy(dst, header->orig_name ? header->orig_name : header->name->base, header->name->len);
        dst += header->name->len;
        *dst++ = ':';
        *dst++ = ' ';
        memcpy(dst, header->value.base, header->value.len);
        dst += header->value.len;
        *dst++ = '\r';
        *dst++ = '\n';
    }

    return dst - buf;
}

static size_t flatten_headers(char *buf, vhttp_req_t *req, const char *connection)
{
    vhttp_context_t *ctx = req->conn->ctx;
    char *dst = buf;

    assert(req->res.status <= 999);

    /* send essential headers with the first chars uppercased for max. interoperability (#72) */
    if (req->res.content_length != SIZE_MAX) {
        dst += sprintf(dst, "HTTP/1.1 %d %s\r\nConnection: %s\r\nContent-Length: %zu\r\n", req->res.status, req->res.reason,
                       connection, req->res.content_length);
    } else {
        dst += sprintf(dst, "HTTP/1.1 %d %s\r\nConnection: %s\r\n", req->res.status, req->res.reason, connection);
    }
    if (ctx->globalconf->server_name.len) {
        dst += sprintf(dst, "Server: %s\r\n", ctx->globalconf->server_name.base);
    }

    dst += flatten_res_headers(dst, req);
    *dst++ = '\r';
    *dst++ = '\n';

    return dst - buf;
}

static int should_use_chunked_encoding(vhttp_req_t *req)
{
    if (req->is_tunnel_req)
        return 0;
    if (req->version != 0x101)
        return 0;
    /* do nothing if content-length is known */
    if (req->res.content_length != SIZE_MAX)
        return 0;
    /* RFC 2616 4.4 states that the following status codes (and response to a HEAD method) should not include message body */
    if ((100 <= req->res.status && req->res.status <= 199) || req->res.status == 204 || req->res.status == 304)
        return 0;
    if (vhttp_memis(req->input.method.base, req->input.method.len, vhttp_STRLIT("HEAD")))
        return 0;

    return 1;
}

static void setup_chunked(struct st_vhttp_http1_finalostream_t *self, vhttp_req_t *req)
{
    if (should_use_chunked_encoding(req)) {
        vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_TRANSFER_ENCODING, NULL, vhttp_STRLIT("chunked"));
        self->chunked_buf = vhttp_mem_alloc_pool_aligned(&req->pool, 1, sizeof(size_t) * 2 + sizeof("\r\n"));
    }
}

static void encode_chunked(vhttp_sendvec_t *prefix, vhttp_sendvec_t *suffix, vhttp_send_state_t state, size_t chunk_size,
                           int send_trailers, char *buffer)
{
    vhttp_sendvec_init_raw(prefix, NULL, 0);
    vhttp_sendvec_init_raw(suffix, NULL, 0);

    /* create chunk header and output data */
    if (chunk_size != 0) {
        prefix->raw = buffer;
        prefix->len = sprintf(buffer, "%zx\r\n", chunk_size);
        if (state != vhttp_SEND_STATE_ERROR) {
            suffix->raw = "\r\n0\r\n\r\n";
            suffix->len = state == vhttp_SEND_STATE_FINAL ? (send_trailers ? 5 : 7) : 2;
        }
    } else if (state == vhttp_SEND_STATE_FINAL) {
        suffix->raw = "0\r\n\r\n";
        suffix->len = send_trailers ? 3 : 5;
    }

    /* if state is error, send a broken chunk to pass the error down to the browser */
    if (state == vhttp_SEND_STATE_ERROR) {
        suffix->raw = "\r\n1\r\n";
        suffix->len = 5;
    }
}

void finalostream_send(vhttp_ostream_t *_self, vhttp_req_t *_req, vhttp_sendvec_t *inbufs, size_t inbufcnt, vhttp_send_state_t send_state)
{
    struct st_vhttp_http1_conn_t *conn = (struct st_vhttp_http1_conn_t *)_req->conn;
    vhttp_sendvec_t bufs[inbufcnt + 1 + 2]; /* 1 for header, 2 for chunked encoding */
    size_t bufcnt = 0, chunked_prefix_index = 0;

    assert(&conn->req == _req);
    assert(_self == &conn->_ostr_final.super);

    if (conn->_ostr_final.informational.write_inflight) {
        conn->_ostr_final.informational.pending_final.inbufs = vhttp_mem_alloc_pool(&conn->req.pool, vhttp_sendvec_t, inbufcnt);
        memcpy(conn->_ostr_final.informational.pending_final.inbufs, inbufs, sizeof(*inbufs) * inbufcnt);
        conn->_ostr_final.informational.pending_final.inbufcnt = inbufcnt;
        conn->_ostr_final.informational.pending_final.send_state = send_state;
        return;
    }

    if (send_state == vhttp_SEND_STATE_ERROR) {
        conn->req.http1_is_persistent = 0;
        conn->req.send_server_timing = 0;
        if (conn->req.upstream_refused) {
            /* to let the client retry, immediately close the connection without sending any data */
            on_send_complete(conn->sock, NULL);
            return;
        }
    }

    if (conn->_ostr_final.state == OSTREAM_STATE_HEAD) {
        /* build headers and send */
        conn->req.timestamps.response_start_at = vhttp_gettimeofday(conn->super.ctx->loop);
        setup_chunked(&conn->_ostr_final, &conn->req);
        if (conn->req.send_server_timing)
            vhttp_add_server_timing_header(&conn->req, conn->_ostr_final.chunked_buf != NULL);

        const char *connection = conn->req.http1_is_persistent ? "keep-alive" : "close";
        if (conn->req.is_tunnel_req && conn->req.res.status == 101 && conn->req.upgrade.base)
            connection = "upgrade";
        size_t headers_est_size =
            flatten_headers_estimate_size(&conn->req, conn->super.ctx->globalconf->server_name.len + strlen(connection));
        vhttp_sendvec_init_raw(bufs + bufcnt, vhttp_mem_alloc_pool(&conn->req.pool, char, headers_est_size), 0);
        bufs[bufcnt].len = flatten_headers(bufs[bufcnt].raw, &conn->req, connection);
        conn->req.header_bytes_sent += bufs[bufcnt].len;
        ++bufcnt;
        vhttp_probe_log_response(&conn->req, conn->_req_index);
        conn->_ostr_final.state = OSTREAM_STATE_BODY;
    }

    if (conn->_ostr_final.chunked_buf != NULL)
        chunked_prefix_index = bufcnt++;

    size_t bytes_sent = 0;
    for (size_t i = 0; i != inbufcnt; ++i) {
        bufs[bufcnt++] = inbufs[i];
        bytes_sent += inbufs[i].len;
    }
    conn->req.bytes_sent += bytes_sent;

    if (conn->_ostr_final.chunked_buf != NULL) {
        encode_chunked(bufs + chunked_prefix_index, bufs + bufcnt, send_state, bytes_sent, conn->req.send_server_timing != 0,
                       conn->_ostr_final.chunked_buf);
        if (bufs[bufcnt].len != 0)
            ++bufcnt;
    }

    if (bufcnt != 0)
        set_req_io_timeout(conn, conn->super.ctx->globalconf->http1.req_io_timeout, req_io_on_timeout);

    vhttp_socket_sendvec(conn->sock, bufs, bufcnt, vhttp_send_state_is_in_progress(send_state) ? on_send_next : on_send_complete);
}

static void on_send_informational_complete(vhttp_socket_t *sock, const char *err);

static void do_send_informational(struct st_vhttp_http1_conn_t *conn)
{
    assert(!conn->_ostr_final.informational.write_inflight && conn->_ostr_final.informational.pending.size != 0);

    conn->_ostr_final.informational.write_inflight = 1;
    vhttp_socket_write(conn->sock, conn->_ostr_final.informational.pending.entries, conn->_ostr_final.informational.pending.size,
                     on_send_informational_complete);
    conn->_ostr_final.informational.pending.size = 0;
}

static void on_send_informational_complete(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_http1_conn_t *conn = sock->data;
    if (err != NULL) {
        close_connection(conn, 1);
        return;
    }

    conn->_ostr_final.informational.write_inflight = 0;

    if (conn->_ostr_final.informational.pending_final.inbufs != NULL) {
        finalostream_send(&conn->_ostr_final.super, &conn->req, conn->_ostr_final.informational.pending_final.inbufs,
                          conn->_ostr_final.informational.pending_final.inbufcnt,
                          conn->_ostr_final.informational.pending_final.send_state);
        return;
    }

    if (conn->_ostr_final.informational.pending.size != 0)
        do_send_informational(conn);
}

static void finalostream_send_informational(vhttp_ostream_t *_self, vhttp_req_t *req)
{
    struct st_vhttp_http1_conn_t *conn = (struct st_vhttp_http1_conn_t *)req->conn;
    assert(_self == &conn->_ostr_final.super);

    size_t len = sizeof("HTTP/1.1  \r\n\r\n") + 3 + strlen(req->res.reason) - 1;
    vhttp_iovec_t buf = vhttp_iovec_init(NULL, len);

    int i;
    for (i = 0; i != req->res.headers.size; ++i)
        buf.len += req->res.headers.entries[i].name->len + req->res.headers.entries[i].value.len + 4;

    buf.base = vhttp_mem_alloc_pool(&req->pool, char, buf.len);
    char *dst = buf.base;
    dst += sprintf(dst, "HTTP/1.1 %d %s\r\n", req->res.status, req->res.reason);
    dst += flatten_res_headers(dst, req);
    *dst++ = '\r';
    *dst++ = '\n';

    req->header_bytes_sent += dst - buf.base;

    vhttp_vector_reserve(&req->pool, &conn->_ostr_final.informational.pending, conn->_ostr_final.informational.pending.size + 1);
    conn->_ostr_final.informational.pending.entries[conn->_ostr_final.informational.pending.size++] = buf;

    if (!conn->_ostr_final.informational.write_inflight)
        do_send_informational(conn);
}

static socklen_t get_sockname(vhttp_conn_t *_conn, struct sockaddr *sa)
{
    struct st_vhttp_http1_conn_t *conn = (void *)_conn;
    return vhttp_socket_getsockname(conn->sock, sa);
}

static socklen_t get_peername(vhttp_conn_t *_conn, struct sockaddr *sa)
{
    struct st_vhttp_http1_conn_t *conn = (void *)_conn;
    return vhttp_socket_getpeername(conn->sock, sa);
}

static ptls_t *get_ptls(vhttp_conn_t *_conn)
{
    struct st_vhttp_http1_conn_t *conn = (void *)_conn;
    assert(conn->sock != NULL && "it never becomes NULL, right?");
    return vhttp_socket_get_ptls(conn->sock);
}

static int skip_tracing(vhttp_conn_t *_conn)
{
    struct st_vhttp_http1_conn_t *conn = (void *)_conn;
    return vhttp_socket_skip_tracing(conn->sock);
}

static int can_zerocopy(vhttp_conn_t *_conn)
{
    struct st_vhttp_http1_conn_t *conn = (void *)_conn;
    return conn->sock->ssl == NULL || vhttp_socket_can_tls_offload(conn->sock);
}

static uint64_t get_req_id(vhttp_req_t *req)
{
    struct st_vhttp_http1_conn_t *conn = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_http1_conn_t, req, req);
    return conn->_req_index;
}

static vhttp_socket_t *steal_socket(vhttp_conn_t *_conn)
{
    struct st_vhttp_http1_conn_t *conn = (void *)_conn;
    vhttp_socket_t *sock = conn->sock;

    if (sock->ssl != NULL)
        return NULL;

    close_connection(conn, 0);
    return sock;
}

#define DEFINE_LOGGER(name)                                                                                                        \
    static vhttp_iovec_t log_##name(vhttp_req_t *req)                                                                                  \
    {                                                                                                                              \
        struct st_vhttp_http1_conn_t *conn = (void *)req->conn;                                                                      \
        return vhttp_socket_log_##name(conn->sock, &req->pool);                                                                      \
    }

DEFINE_LOGGER(tcp_congestion_controller)
DEFINE_LOGGER(tcp_delivery_rate)
DEFINE_LOGGER(ssl_protocol_version)
DEFINE_LOGGER(ssl_session_reused)
DEFINE_LOGGER(ssl_cipher)
DEFINE_LOGGER(ssl_cipher_bits)
DEFINE_LOGGER(ssl_session_id)
DEFINE_LOGGER(ssl_server_name)
DEFINE_LOGGER(ssl_negotiated_protocol)
DEFINE_LOGGER(ssl_ech_config_id)
DEFINE_LOGGER(ssl_ech_kem)
DEFINE_LOGGER(ssl_ech_cipher)
DEFINE_LOGGER(ssl_ech_cipher_bits)
DEFINE_LOGGER(ssl_backend)

#undef DEFINE_LOGGER

static vhttp_iovec_t log_request_index(vhttp_req_t *req)
{
    struct st_vhttp_http1_conn_t *conn = (void *)req->conn;
    char *s = vhttp_mem_alloc_pool(&req->pool, char, sizeof(vhttp_UINT64_LONGEST_STR));
    size_t len = sprintf(s, "%" PRIu64, conn->_req_index);
    return vhttp_iovec_init(s, len);
}

static int foreach_request(vhttp_conn_t *_conn, int (*cb)(vhttp_req_t *req, void *cbdata), void *cbdata)
{
    struct st_vhttp_http1_conn_t *conn = (void *)_conn;
    return cb(&conn->req, cbdata);
}

static void initiate_graceful_shutdown(vhttp_conn_t *_conn)
{
    /* note: nothing special needs to be done for handling graceful shutdown */
}

static const vhttp_conn_callbacks_t h1_callbacks = {
    .get_sockname = get_sockname,
    .get_peername = get_peername,
    .get_ptls = get_ptls,
    .skip_tracing = skip_tracing,
    .close_idle_connection = close_idle_connection,
    .foreach_request = foreach_request,
    .request_shutdown = initiate_graceful_shutdown,
    .can_zerocopy = can_zerocopy,
    .get_req_id = get_req_id,
    .steal_socket = steal_socket,
    .log_ = {{
        .transport =
            {
                .cc_name = log_tcp_congestion_controller,
                .delivery_rate = log_tcp_delivery_rate,
            },
        .ssl =
            {
                .protocol_version = log_ssl_protocol_version,
                .session_reused = log_ssl_session_reused,
                .cipher = log_ssl_cipher,
                .cipher_bits = log_ssl_cipher_bits,
                .session_id = log_ssl_session_id,
                .server_name = log_ssl_server_name,
                .negotiated_protocol = log_ssl_negotiated_protocol,
                .ech_config_id = log_ssl_ech_config_id,
                .ech_kem = log_ssl_ech_kem,
                .ech_cipher = log_ssl_ech_cipher,
                .ech_cipher_bits = log_ssl_ech_cipher_bits,
                .backend = log_ssl_backend,
            },
        .http1 =
            {
                .request_index = log_request_index,
            },
    }},
};

static int conn_is_h1(vhttp_conn_t *conn)
{
    return conn->callbacks == &h1_callbacks;
}

void vhttp_http1_accept(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock, struct timeval connected_at)
{
    struct st_vhttp_http1_conn_t *conn =
        (void *)vhttp_create_connection(sizeof(*conn), ctx->ctx, ctx->hosts, connected_at, &h1_callbacks);

    /* zero-fill all properties expect req */
    memset((char *)conn + sizeof(conn->super), 0, offsetof(struct st_vhttp_http1_conn_t, req) - sizeof(conn->super));

    /* init properties that need to be non-zero */
    conn->sock = sock;
    sock->data = conn;

    vhttp_PROBE_CONN(H1_ACCEPT, &conn->super, conn->sock, &conn->super, vhttp_conn_get_uuid(&conn->super));

    init_request(conn);
    reqread_start(conn);
}

void vhttp_http1_upgrade(vhttp_req_t *req, vhttp_iovec_t *inbufs, size_t inbufcnt, vhttp_http1_upgrade_cb on_complete, void *user_data)
{

    assert(conn_is_h1(req->conn));
    struct st_vhttp_http1_conn_t *conn = (void *)req->conn;

    vhttp_iovec_t *bufs = alloca(sizeof(vhttp_iovec_t) * (inbufcnt + 1));

    conn->upgrade.data = user_data;
    conn->upgrade.cb = on_complete;

    bufs[0].base = vhttp_mem_alloc_pool(
        &conn->req.pool, char,
        flatten_headers_estimate_size(&conn->req, conn->super.ctx->globalconf->server_name.len + sizeof("upgrade") - 1));
    bufs[0].len = flatten_headers(bufs[0].base, &conn->req, conn->req.res.status == 101 ? "upgrade" : "close");
    vhttp_memcpy(bufs + 1, inbufs, sizeof(vhttp_iovec_t) * inbufcnt);

    vhttp_socket_write(conn->sock, bufs, inbufcnt + 1, on_upgrade_complete);
}
