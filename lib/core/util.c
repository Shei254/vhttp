/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Satoh Hiroh
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
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "vhttp.h"
#include "vhttp/http1.h"
#include "vhttp/http2.h"
#include "vhttp/hiredis_.h"

struct st_vhttp_accept_data_t {
    vhttp_accept_ctx_t *ctx;
    vhttp_socket_t *sock;
    vhttp_timer_t timeout;
    struct timeval connected_at;
};

struct st_vhttp_memcached_resumption_accept_data_t {
    struct st_vhttp_accept_data_t super;
    vhttp_memcached_req_t *get_req;
};

struct st_vhttp_redis_resumption_accept_data_t {
    struct st_vhttp_accept_data_t super;
    vhttp_redis_command_t *get_command;
};

static void on_accept_timeout(vhttp_timer_t *entry);
static void on_redis_accept_timeout(vhttp_timer_t *entry);
static void on_memcached_accept_timeout(vhttp_timer_t *entry);

static struct {
    struct {
        vhttp_memcached_context_t *ctx;
    } memcached;
    struct {
        vhttp_iovec_t host;
        uint16_t port;
        vhttp_iovec_t prefix;
    } redis;
    unsigned expiration;
} async_resumption_context;

static struct st_vhttp_accept_data_t *create_accept_data(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock, struct timeval connected_at,
                                                       vhttp_timer_cb timeout_cb, size_t sz)
{
    struct st_vhttp_accept_data_t *data = vhttp_mem_alloc(sz);
    data->ctx = ctx;
    data->sock = sock;
    vhttp_timer_init(&data->timeout, timeout_cb);
    vhttp_timer_link(ctx->ctx->loop, ctx->ctx->globalconf->handshake_timeout, &data->timeout);
    data->connected_at = connected_at;
    return data;
}

static struct st_vhttp_accept_data_t *create_default_accept_data(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock,
                                                               struct timeval connected_at)
{
    struct st_vhttp_accept_data_t *data =
        create_accept_data(ctx, sock, connected_at, on_accept_timeout, sizeof(struct st_vhttp_accept_data_t));
    return data;
}

static struct st_vhttp_accept_data_t *create_redis_accept_data(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock, struct timeval connected_at)
{
    struct st_vhttp_redis_resumption_accept_data_t *data = (struct st_vhttp_redis_resumption_accept_data_t *)create_accept_data(
        ctx, sock, connected_at, on_redis_accept_timeout, sizeof(struct st_vhttp_redis_resumption_accept_data_t));
    data->get_command = NULL;
    return &data->super;
}

static struct st_vhttp_accept_data_t *create_memcached_accept_data(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock,
                                                                 struct timeval connected_at)
{
    struct st_vhttp_memcached_resumption_accept_data_t *data = (struct st_vhttp_memcached_resumption_accept_data_t *)create_accept_data(
        ctx, sock, connected_at, on_memcached_accept_timeout, sizeof(struct st_vhttp_memcached_resumption_accept_data_t));
    data->get_req = NULL;
    return &data->super;
}

static void destroy_accept_data(struct st_vhttp_accept_data_t *data)
{
    vhttp_timer_unlink(&data->timeout);
    free(data);
}

static void destroy_default_accept_data(struct st_vhttp_accept_data_t *_accept_data)
{
    destroy_accept_data(_accept_data);
}

static void destroy_redis_accept_data(struct st_vhttp_accept_data_t *_accept_data)
{
    struct st_vhttp_redis_resumption_accept_data_t *accept_data = (struct st_vhttp_redis_resumption_accept_data_t *)_accept_data;
    assert(accept_data->get_command == NULL);
    destroy_accept_data(&accept_data->super);
}

static void destroy_memcached_accept_data(struct st_vhttp_accept_data_t *_accept_data)
{
    struct st_vhttp_memcached_resumption_accept_data_t *accept_data =
        (struct st_vhttp_memcached_resumption_accept_data_t *)_accept_data;
    assert(accept_data->get_req == NULL);
    destroy_accept_data(&accept_data->super);
}

static struct {
    struct st_vhttp_accept_data_t *(*create)(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock, struct timeval connected_at);
    void (*destroy)(struct st_vhttp_accept_data_t *accept_data);
} accept_data_callbacks = {
    create_default_accept_data,
    destroy_default_accept_data,
};

static void memcached_resumption_on_get(vhttp_iovec_t session_data, void *_accept_data)
{
    struct st_vhttp_memcached_resumption_accept_data_t *accept_data = _accept_data;
    accept_data->get_req = NULL;
    vhttp_socket_ssl_resume_server_handshake(accept_data->super.sock, session_data);
}

static void memcached_resumption_get(vhttp_socket_t *sock, vhttp_iovec_t session_id)
{
    struct st_vhttp_memcached_resumption_accept_data_t *data = sock->data;

    data->get_req = vhttp_memcached_get(async_resumption_context.memcached.ctx, data->super.ctx->libmemcached_receiver, session_id,
                                      memcached_resumption_on_get, data, vhttp_MEMCACHED_ENCODE_KEY | vhttp_MEMCACHED_ENCODE_VALUE);
}

static void memcached_resumption_new(vhttp_socket_t *sock, vhttp_iovec_t session_id, vhttp_iovec_t session_data)
{
    vhttp_memcached_set(async_resumption_context.memcached.ctx, session_id, session_data,
                      (uint32_t)time(NULL) + async_resumption_context.expiration,
                      vhttp_MEMCACHED_ENCODE_KEY | vhttp_MEMCACHED_ENCODE_VALUE);
}

void vhttp_accept_setup_memcached_ssl_resumption(vhttp_memcached_context_t *memc, unsigned expiration)
{
    async_resumption_context.memcached.ctx = memc;
    async_resumption_context.expiration = expiration;
    vhttp_socket_ssl_async_resumption_init(memcached_resumption_get, memcached_resumption_new);
    accept_data_callbacks.create = create_memcached_accept_data;
    accept_data_callbacks.destroy = destroy_memcached_accept_data;
}

static void on_redis_connect(void)
{
    vhttp_error_printf("connected to redis at %s:%" PRIu16 "\n", async_resumption_context.redis.host.base,
                     async_resumption_context.redis.port);
}

static void on_redis_close(const char *errstr)
{
    if (errstr == NULL) {
        vhttp_error_printf("disconnected from redis at %s:%" PRIu16 "\n", async_resumption_context.redis.host.base,
                         async_resumption_context.redis.port);
    } else {
        vhttp_error_printf("redis connection failure: %s\n", errstr);
    }
}

static void dispose_redis_connection(void *client)
{
    vhttp_redis_free((vhttp_redis_client_t *)client);
}

static vhttp_redis_client_t *get_redis_client(vhttp_context_t *ctx)
{
    static size_t key = SIZE_MAX;
    vhttp_redis_client_t **client = (vhttp_redis_client_t **)vhttp_context_get_storage(ctx, &key, dispose_redis_connection);
    if (*client == NULL) {
        *client = vhttp_redis_create_client(ctx->loop, sizeof(vhttp_redis_client_t));
        (*client)->on_connect = on_redis_connect;
        (*client)->on_close = on_redis_close;
    }
    return *client;
}

#define BASE64_LENGTH(len) (((len) + 2) / 3 * 4 + 1)

static vhttp_iovec_t build_redis_key(vhttp_iovec_t session_id, vhttp_iovec_t prefix)
{
    vhttp_iovec_t key;
    key.base = vhttp_mem_alloc(prefix.len + BASE64_LENGTH(session_id.len));
    if (prefix.len != 0) {
        memcpy(key.base, prefix.base, prefix.len);
    }
    key.len = prefix.len;
    key.len += vhttp_base64_encode(key.base + key.len, session_id.base, session_id.len, 1);
    return key;
}

static vhttp_iovec_t build_redis_value(vhttp_iovec_t session_data)
{
    vhttp_iovec_t value;
    value.base = vhttp_mem_alloc(BASE64_LENGTH(session_data.len));
    value.len = vhttp_base64_encode(value.base, session_data.base, session_data.len, 1);
    return value;
}

#undef BASE64_LENGTH

static void redis_resumption_on_get(redisReply *reply, void *_accept_data, const char *errstr)
{
    struct st_vhttp_redis_resumption_accept_data_t *accept_data = _accept_data;
    accept_data->get_command = NULL;

    vhttp_iovec_t session_data;
    if (reply != NULL && reply->type == REDIS_REPLY_STRING) {
        session_data = vhttp_decode_base64url(NULL, reply->str, reply->len);
    } else {
        session_data = vhttp_iovec_init(NULL, 0);
    }

    vhttp_socket_ssl_resume_server_handshake(accept_data->super.sock, session_data);

    if (session_data.base != NULL)
        free(session_data.base);
}

static void on_redis_resumption_get_failed(vhttp_timer_t *timeout_entry)
{
    struct st_vhttp_redis_resumption_accept_data_t *accept_data =
        vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_redis_resumption_accept_data_t, super.timeout, timeout_entry);
    accept_data->get_command = NULL;
    vhttp_socket_ssl_resume_server_handshake(accept_data->super.sock, vhttp_iovec_init(NULL, 0));
    vhttp_timer_unlink(timeout_entry);
}

static void redis_resumption_get(vhttp_socket_t *sock, vhttp_iovec_t session_id)
{
    struct st_vhttp_redis_resumption_accept_data_t *accept_data = sock->data;
    vhttp_redis_client_t *client = get_redis_client(accept_data->super.ctx->ctx);

    if (client->state == vhttp_REDIS_CONNECTION_STATE_CONNECTED) {
        vhttp_iovec_t key = build_redis_key(session_id, async_resumption_context.redis.prefix);
        accept_data->get_command = vhttp_redis_command(client, redis_resumption_on_get, accept_data, "GET %s", key.base);
        free(key.base);
    } else {
        if (client->state == vhttp_REDIS_CONNECTION_STATE_CLOSED) {
            // try to connect
            vhttp_redis_connect(client, async_resumption_context.redis.host.base, async_resumption_context.redis.port);
        }
        // abort resumption
        vhttp_timer_unlink(&accept_data->super.timeout);
        accept_data->super.timeout.cb = on_redis_resumption_get_failed;
        vhttp_timer_link(accept_data->super.ctx->ctx->loop, 0, &accept_data->super.timeout);
    }
}

static void redis_resumption_new(vhttp_socket_t *sock, vhttp_iovec_t session_id, vhttp_iovec_t session_data)
{
    struct st_vhttp_redis_resumption_accept_data_t *accept_data = sock->data;
    vhttp_redis_client_t *client = get_redis_client(accept_data->super.ctx->ctx);

    if (client->state == vhttp_REDIS_CONNECTION_STATE_CLOSED) {
        // try to connect
        vhttp_redis_connect(client, async_resumption_context.redis.host.base, async_resumption_context.redis.port);
    }

    vhttp_iovec_t key = build_redis_key(session_id, async_resumption_context.redis.prefix);
    vhttp_iovec_t value = build_redis_value(session_data);
    vhttp_redis_command(client, NULL, NULL, "SETEX %s %d %s", key.base, async_resumption_context.expiration * 10, value.base);
    free(key.base);
    free(value.base);
}

void vhttp_accept_setup_redis_ssl_resumption(const char *host, uint16_t port, unsigned expiration, const char *prefix)
{
    async_resumption_context.redis.host = vhttp_strdup(NULL, host, SIZE_MAX);
    async_resumption_context.redis.port = port;
    async_resumption_context.redis.prefix = vhttp_strdup(NULL, prefix, SIZE_MAX);
    async_resumption_context.expiration = expiration;

    vhttp_socket_ssl_async_resumption_init(redis_resumption_get, redis_resumption_new);

    accept_data_callbacks.create = create_redis_accept_data;
    accept_data_callbacks.destroy = destroy_redis_accept_data;
}

static void accept_timeout(struct st_vhttp_accept_data_t *data)
{
    /* TODO log */
    vhttp_socket_t *sock = data->sock;
    accept_data_callbacks.destroy(data);
    vhttp_socket_close(sock);
}

static void on_accept_timeout(vhttp_timer_t *entry)
{
    struct st_vhttp_accept_data_t *data = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_accept_data_t, timeout, entry);
    accept_timeout(data);
}

static void on_redis_accept_timeout(vhttp_timer_t *entry)
{
    struct st_vhttp_redis_resumption_accept_data_t *data =
        vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_redis_resumption_accept_data_t, super.timeout, entry);
    if (data->get_command != NULL) {
        data->get_command->cb = NULL;
        data->get_command = NULL;
    }
    accept_timeout(&data->super);
}

static void on_memcached_accept_timeout(vhttp_timer_t *entry)
{
    struct st_vhttp_memcached_resumption_accept_data_t *data =
        vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_memcached_resumption_accept_data_t, super.timeout, entry);
    if (data->get_req != NULL) {
        vhttp_memcached_cancel_get(async_resumption_context.memcached.ctx, data->get_req);
        data->get_req = NULL;
    }
    accept_timeout(&data->super);
}

static void on_ssl_handshake_complete(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_accept_data_t *data = sock->data;
    sock->data = NULL;

    if (err != NULL) {
        ++data->ctx->ctx->ssl.errors;
        vhttp_socket_close(sock);
        goto Exit;
    }

    /* stats for handshake */
    struct timeval handshake_completed_at = vhttp_gettimeofday(data->ctx->ctx->loop);
    int64_t handshake_time = vhttp_timeval_subtract(&data->connected_at, &handshake_completed_at);
    if (vhttp_socket_get_ssl_session_reused(sock)) {
        ++data->ctx->ctx->ssl.handshake_resume;
        data->ctx->ctx->ssl.handshake_accum_time_resume += handshake_time;
    } else {
        ++data->ctx->ctx->ssl.handshake_full;
        data->ctx->ctx->ssl.handshake_accum_time_full += handshake_time;
    }

    vhttp_iovec_t proto = vhttp_socket_ssl_get_selected_protocol(sock);
    const vhttp_iovec_t *ident;
    for (ident = vhttp_http2_alpn_protocols; ident->len != 0; ++ident) {
        if (proto.len == ident->len && memcmp(proto.base, ident->base, proto.len) == 0) {
            /* connect as http2 */
            ++data->ctx->ctx->ssl.alpn_h2;
            vhttp_http2_accept(data->ctx, sock, data->connected_at);
            goto Exit;
        }
    }
    /* connect as http1 */
    if (proto.len != 0)
        ++data->ctx->ctx->ssl.alpn_h1;
    vhttp_http1_accept(data->ctx, sock, data->connected_at);

Exit:
    accept_data_callbacks.destroy(data);
}

static ssize_t parse_proxy_line(char *src, size_t len, struct sockaddr *sa, socklen_t *salen)
{
#define CHECK_EOF()                                                                                                                \
    if (p == end)                                                                                                                  \
    return -2
#define EXPECT_CHAR(ch)                                                                                                            \
    do {                                                                                                                           \
        CHECK_EOF();                                                                                                               \
        if (*p++ != ch)                                                                                                            \
            return -1;                                                                                                             \
    } while (0)
#define SKIP_TO_WS()                                                                                                               \
    do {                                                                                                                           \
        do {                                                                                                                       \
            CHECK_EOF();                                                                                                           \
        } while (*p++ != ' ');                                                                                                     \
        --p;                                                                                                                       \
    } while (0)

    char *p = src, *end = p + len;
    void *addr;
    in_port_t *port;

    /* "PROXY "*/
    EXPECT_CHAR('P');
    EXPECT_CHAR('R');
    EXPECT_CHAR('O');
    EXPECT_CHAR('X');
    EXPECT_CHAR('Y');
    EXPECT_CHAR(' ');

    /* "TCP[46] " */
    CHECK_EOF();
    if (*p++ != 'T') {
        *salen = 0; /* indicate that no data has been obtained */
        goto SkipToEOL;
    }
    EXPECT_CHAR('C');
    EXPECT_CHAR('P');
    CHECK_EOF();
    switch (*p++) {
    case '4':
        *salen = sizeof(struct sockaddr_in);
        memset(sa, 0, sizeof(struct sockaddr_in));
        sa->sa_family = AF_INET;
        addr = &((struct sockaddr_in *)sa)->sin_addr;
        port = &((struct sockaddr_in *)sa)->sin_port;
        break;
    case '6':
        *salen = sizeof(struct sockaddr_in6);
        memset(sa, 0, sizeof(struct sockaddr_in6));
        sa->sa_family = AF_INET6;
        addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
        port = &((struct sockaddr_in6 *)sa)->sin6_port;
        break;
    default:
        return -1;
    }
    EXPECT_CHAR(' ');

    /* parse peer address */
    char *addr_start = p;
    SKIP_TO_WS();
    *p = '\0';
    if (inet_pton(sa->sa_family, addr_start, addr) != 1)
        return -1;
    *p++ = ' ';

    /* skip local address */
    SKIP_TO_WS();
    ++p;

    /* parse peer port */
    char *port_start = p;
    SKIP_TO_WS();
    *p = '\0';
    unsigned short usval;
    if (sscanf(port_start, "%hu", &usval) != 1)
        return -1;
    *port = htons(usval);
    *p++ = ' ';

SkipToEOL:
    do {
        CHECK_EOF();
    } while (*p++ != '\r');
    CHECK_EOF();
    if (*p++ != '\n')
        return -2;
    return p - src;

#undef CHECK_EOF
#undef EXPECT_CHAR
#undef SKIP_TO_WS
}

static void on_read_proxy_line(vhttp_socket_t *sock, const char *err)
{
    struct st_vhttp_accept_data_t *data = sock->data;

    if (err != NULL) {
        accept_data_callbacks.destroy(data);
        vhttp_socket_close(sock);
        return;
    }

    struct sockaddr_storage addr;
    socklen_t addrlen;
    ssize_t r = parse_proxy_line(sock->input->bytes, sock->input->size, (void *)&addr, &addrlen);
    switch (r) {
    case -1: /* error, just pass the input to the next handler */
        break;
    case -2: /* incomplete */
        return;
    default:
        vhttp_buffer_consume(&sock->input, r);
        if (addrlen != 0)
            vhttp_socket_setpeername(sock, (void *)&addr, addrlen);
        break;
    }

    if (data->ctx->ssl_ctx != NULL) {
        vhttp_socket_ssl_handshake(sock, data->ctx->ssl_ctx, NULL, vhttp_iovec_init(NULL, 0), on_ssl_handshake_complete);
    } else {
        struct st_vhttp_accept_data_t *data = sock->data;
        sock->data = NULL;
        vhttp_http1_accept(data->ctx, sock, data->connected_at);
        accept_data_callbacks.destroy(data);
    }
}

void vhttp_accept(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock)
{
    struct timeval connected_at = vhttp_gettimeofday(ctx->ctx->loop);

    if (ctx->expect_proxy_line || ctx->ssl_ctx != NULL) {
        sock->data = accept_data_callbacks.create(ctx, sock, connected_at);
        if (ctx->expect_proxy_line) {
            vhttp_socket_read_start(sock, on_read_proxy_line);
        } else {
            vhttp_socket_ssl_handshake(sock, ctx->ssl_ctx, NULL, vhttp_iovec_init(NULL, 0), on_ssl_handshake_complete);
        }
    } else {
        vhttp_http1_accept(ctx, sock, connected_at);
    }
}

size_t vhttp_stringify_protocol_version(char *dst, int version)
{
    char *p = dst;

    if (version < 0x200) {
        assert(version <= 0x109);
#define PREFIX "HTTP/1."
        memcpy(p, PREFIX, sizeof(PREFIX) - 1);
        p += sizeof(PREFIX) - 1;
#undef PREFIX
        *p++ = '0' + (version & 0xff);
    } else {
#define PREFIX "HTTP/"
        memcpy(p, PREFIX, sizeof(PREFIX) - 1);
        p += sizeof(PREFIX) - 1;
#undef PREFIX
        *p++ = (version >> 8) + '0';
    }

    *p = '\0';
    return p - dst;
}

size_t vhttp_stringify_proxy_header(vhttp_conn_t *conn, char *buf)
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    size_t strlen;
    uint16_t peerport;
    char *dst = buf;

    if ((sslen = conn->callbacks->get_peername(conn, (void *)&ss)) == 0)
        goto Unknown;
    switch (ss.ss_family) {
    case AF_INET:
        memcpy(dst, "PROXY TCP4 ", 11);
        dst += 11;
        break;
    case AF_INET6:
        memcpy(dst, "PROXY TCP6 ", 11);
        dst += 11;
        break;
    default:
        goto Unknown;
    }
    if ((strlen = vhttp_socket_getnumerichost((void *)&ss, sslen, dst)) == SIZE_MAX)
        goto Unknown;
    dst += strlen;
    *dst++ = ' ';

    peerport = vhttp_socket_getport((void *)&ss);

    if ((sslen = conn->callbacks->get_sockname(conn, (void *)&ss)) == 0)
        goto Unknown;
    if ((strlen = vhttp_socket_getnumerichost((void *)&ss, sslen, dst)) == SIZE_MAX)
        goto Unknown;
    dst += strlen;
    *dst++ = ' ';

    dst += sprintf(dst, "%" PRIu16 " %" PRIu16 "\r\n", peerport, (uint16_t)vhttp_socket_getport((void *)&ss));

    return dst - buf;

Unknown:
    memcpy(buf, "PROXY UNKNOWN\r\n", 15);
    return 15;
}

static vhttp_iovec_t to_push_path(vhttp_mem_pool_t *pool, vhttp_iovec_t url, vhttp_iovec_t base_path, const vhttp_url_scheme_t *input_scheme,
                                vhttp_iovec_t input_authority, const vhttp_url_scheme_t *base_scheme, vhttp_iovec_t *base_authority,
                                int allow_cross_origin_push)
{
    vhttp_url_t parsed, resolved;

    /* check the authority, and extract absolute path */
    if (vhttp_url_parse_relative(pool, url.base, url.len, &parsed) != 0)
        goto Invalid;

    /* fast-path for abspath form */
    if (base_scheme == NULL && parsed.scheme == NULL && parsed.authority.base == NULL && url.len != 0 && url.base[0] == '/') {
        return vhttp_strdup(pool, url.base, url.len);
    }

    /* check scheme and authority if given URL contains either of the two, or if base is specified */
    vhttp_url_t base = {input_scheme, input_authority, {NULL}, base_path, 65535};
    if (base_scheme != NULL) {
        base.scheme = base_scheme;
        base.authority = *base_authority;
    }
    vhttp_url_resolve(pool, &base, &parsed, &resolved);
    if (input_scheme != resolved.scheme)
        goto Invalid;
    if (!allow_cross_origin_push &&
        !vhttp_lcstris(input_authority.base, input_authority.len, resolved.authority.base, resolved.authority.len))
        goto Invalid;

    return resolved.path;

Invalid:
    return vhttp_iovec_init(NULL, 0);
}

void vhttp_extract_push_path_from_link_header(vhttp_mem_pool_t *pool, const char *value, size_t value_len, vhttp_iovec_t base_path,
                                            const vhttp_url_scheme_t *input_scheme, vhttp_iovec_t input_authority,
                                            const vhttp_url_scheme_t *base_scheme, vhttp_iovec_t *base_authority,
                                            void (*cb)(void *ctx, const char *path, size_t path_len, int is_critical), void *cb_ctx,
                                            vhttp_iovec_t *filtered_value, int allow_cross_origin_push)
{
    vhttp_iovec_t iter = vhttp_iovec_init(value, value_len), token_value;
    const char *token;
    size_t token_len;
    *filtered_value = vhttp_iovec_init(NULL, 0);

#define PUSH_FILTERED_VALUE(s, e)                                                                                                  \
    do {                                                                                                                           \
        if (filtered_value->len != 0) {                                                                                            \
            memcpy(filtered_value->base + filtered_value->len, ", ", 2);                                                           \
            filtered_value->len += 2;                                                                                              \
        }                                                                                                                          \
        memcpy(filtered_value->base + filtered_value->len, (s), (e) - (s));                                                        \
        filtered_value->len += (e) - (s);                                                                                          \
    } while (0)

    /* extract URL values from Link: </pushed.css>; rel=preload */
    do {
        if ((token = vhttp_next_token(&iter, ';', ',', &token_len, NULL)) == NULL)
            break;
        /* first element should be <URL> */
        if (!(token_len >= 2 && token[0] == '<' && token[token_len - 1] == '>'))
            break;
        vhttp_iovec_t url_with_brackets = vhttp_iovec_init(token, token_len);
        /* find rel=preload */
        int preload = 0, nopush = 0, push_only = 0, critical = 0;
        while ((token = vhttp_next_token(&iter, ';', ',', &token_len, &token_value)) != NULL &&
               !vhttp_memis(token, token_len, vhttp_STRLIT(","))) {
            if (vhttp_lcstris(token, token_len, vhttp_STRLIT("rel")) &&
                vhttp_lcstris(token_value.base, token_value.len, vhttp_STRLIT("preload"))) {
                preload = 1;
            } else if (vhttp_lcstris(token, token_len, vhttp_STRLIT("nopush"))) {
                nopush = 1;
            } else if (vhttp_lcstris(token, token_len, vhttp_STRLIT("x-http2-push-only"))) {
                push_only = 1;
            } else if (vhttp_lcstris(token, token_len, vhttp_STRLIT("critical"))) {
                critical = 1;
            }
        }
        /* push the path */
        if (!nopush && preload) {
            vhttp_iovec_t path = to_push_path(pool, vhttp_iovec_init(url_with_brackets.base + 1, url_with_brackets.len - 2), base_path,
                                            input_scheme, input_authority, base_scheme, base_authority, allow_cross_origin_push);
            if (path.len != 0)
                (*cb)(cb_ctx, path.base, path.len, critical);
        }
        /* store the elements that needs to be preserved to filtered_value */
        if (push_only) {
            if (filtered_value->base == NULL) {
                /* the max. size of filtered_value would be x2 in the worst case, when "," is converted to ", " */
                filtered_value->base = vhttp_mem_alloc_pool(pool, char, value_len * 2);
                const char *prev_comma = vhttp_memrchr(value, ',', url_with_brackets.base - value);
                if (prev_comma != NULL)
                    PUSH_FILTERED_VALUE(value, prev_comma);
            }
        } else if (filtered_value->base != NULL) {
            PUSH_FILTERED_VALUE(url_with_brackets.base, token != NULL ? token : value + value_len);
        }
    } while (token != NULL);

    if (filtered_value->base != NULL) {
        if (token != NULL)
            PUSH_FILTERED_VALUE(token, value + value_len);
    } else {
        *filtered_value = vhttp_iovec_init(value, value_len);
    }

#undef PUSH_FILTERED_VALUE
}

int vhttp_get_compressible_types(const vhttp_headers_t *headers)
{
    size_t header_index;
    int compressible_types = 0;

    for (header_index = 0; header_index != headers->size; ++header_index) {
        const vhttp_header_t *header = headers->entries + header_index;
        if (vhttp_UNLIKELY(header->name == &vhttp_TOKEN_ACCEPT_ENCODING->buf)) {
            vhttp_iovec_t iter = vhttp_iovec_init(header->value.base, header->value.len);
            const char *token = NULL;
            size_t token_len = 0;
            while ((token = vhttp_next_token(&iter, ',', ',', &token_len, NULL)) != NULL) {
                if (vhttp_lcstris(token, token_len, vhttp_STRLIT("gzip")))
                    compressible_types |= vhttp_COMPRESSIBLE_GZIP;
                else if (vhttp_lcstris(token, token_len, vhttp_STRLIT("br")))
                    compressible_types |= vhttp_COMPRESSIBLE_BROTLI;
                else if (vhttp_lcstris(token, token_len, vhttp_STRLIT("zstd")))
                    compressible_types |= vhttp_COMPRESSIBLE_ZSTD;
            }
        }
    }

    return compressible_types;
}

vhttp_iovec_t vhttp_build_destination(vhttp_req_t *req, const char *prefix, size_t prefix_len, int use_path_normalized)
{
    vhttp_iovec_t parts[4];
    size_t num_parts = 0;
    int conf_ends_with_slash = req->pathconf->path.base[req->pathconf->path.len - 1] == '/', prefix_ends_with_slash;

    /* destination starts with given prefix, if any */
    if (prefix_len != 0) {
        parts[num_parts++] = vhttp_iovec_init(prefix, prefix_len);
        prefix_ends_with_slash = prefix[prefix_len - 1] == '/';
    } else {
        prefix_ends_with_slash = 0;
    }

    /* make adjustments depending on the trailing slashes */
    if (conf_ends_with_slash != prefix_ends_with_slash) {
        if (conf_ends_with_slash) {
            parts[num_parts++] = vhttp_iovec_init(vhttp_STRLIT("/"));
        } else {
            if (req->path_normalized.len != req->pathconf->path.len)
                parts[num_parts - 1].len -= 1;
        }
    }

    /* append suffix path and query */

    if (use_path_normalized) {
        parts[num_parts++] = vhttp_uri_escape(&req->pool, req->path_normalized.base + req->pathconf->path.len,
                                            req->path_normalized.len - req->pathconf->path.len, "/@:");
        if (req->query_at != SIZE_MAX) {
            parts[num_parts++] = vhttp_iovec_init(req->path.base + req->query_at, req->path.len - req->query_at);
        }
    } else {
        if (req->path.len > 1) {
            /*
             * When proxying, we want to modify the input URL as little
             * as possible. We use norm_indexes to find the start of
             * the path we want to forward.
             */
            size_t next_unnormalized;
            if (req->norm_indexes && req->pathconf->path.len > 1) {
                next_unnormalized = req->norm_indexes[req->pathconf->path.len - 1];
            } else {
                next_unnormalized = req->pathconf->path.len;
            }

            /*
             * Special case: the input path didn't have any '/' including the first,
             * so the first character is actually found at '0'
             */
            if (req->path.base[0] != '/' && next_unnormalized == 1) {
                next_unnormalized = 0;
            }
            parts[num_parts++] = (vhttp_iovec_t){req->path.base + next_unnormalized, req->path.len - next_unnormalized};
        }
    }

    return vhttp_concat_list(&req->pool, parts, num_parts);
}

#define SERVER_TIMING_DURATION_LONGEST_STR "dur=" vhttp_INT32_LONGEST_STR ".000"

size_t stringify_duration(char *buf, int64_t usec)
{
    int32_t msec = (int32_t)(usec / 1000);
    usec -= ((int64_t)msec * 1000);
    char *pos = buf;
    pos += sprintf(pos, "dur=%" PRId32, msec);
    if (usec != 0) {
        *pos++ = '.';
        int denom;
        for (denom = 100; denom != 0; denom /= 10) {
            int d = (int)usec / denom;
            *pos++ = '0' + d;
            usec -= d * denom;
            if (usec == 0)
                break;
        }
    }
    return pos - buf;
}

#define DELIMITER ", "
#define ELEMENT_LONGEST_STR(name) name "; " SERVER_TIMING_DURATION_LONGEST_STR

static void emit_server_timing_element(vhttp_req_t *req, vhttp_iovec_t *dst, const char *name,
                                       int (*compute_func)(vhttp_req_t *, int64_t *), size_t max_len)
{
    int64_t usec;
    if (compute_func(req, &usec) == 0)
        return;
    if (dst->len == 0) {
        if (max_len != SIZE_MAX)
            dst->base = vhttp_mem_alloc_pool(&req->pool, *dst->base, max_len);
    } else {
        dst->base[dst->len++] = ',';
        dst->base[dst->len++] = ' ';
    }
    size_t name_len = strlen(name);
    memcpy(dst->base + dst->len, name, name_len);
    dst->len += name_len;
    dst->base[dst->len++] = ';';
    dst->base[dst->len++] = ' ';
    dst->len += stringify_duration(dst->base + dst->len, usec);
}

void vhttp_add_server_timing_header(vhttp_req_t *req, int uses_trailer)
{
    /* caller needs to make sure that trailers can be used */
    if (0x101 <= req->version && req->version < 0x200)
        assert(req->content_length == SIZE_MAX);

    /* emit timings */
    vhttp_iovec_t dst = {NULL};

#define LONGEST_STR                                                                                                                \
    ELEMENT_LONGEST_STR("connect")                                                                                                 \
    DELIMITER ELEMENT_LONGEST_STR("request-header") DELIMITER ELEMENT_LONGEST_STR("request-body")                                  \
        DELIMITER ELEMENT_LONGEST_STR("request-total") DELIMITER ELEMENT_LONGEST_STR("process")                                    \
            DELIMITER ELEMENT_LONGEST_STR("proxy.idle") DELIMITER ELEMENT_LONGEST_STR("proxy.connect")                             \
                DELIMITER ELEMENT_LONGEST_STR("proxy.request") DELIMITER ELEMENT_LONGEST_STR("proxy.process")
    size_t max_len = sizeof(LONGEST_STR) - 1;

    if ((req->send_server_timing & vhttp_SEND_SERVER_TIMING_BASIC) != 0) {
        emit_server_timing_element(req, &dst, "connect", vhttp_time_compute_connect_time, max_len);
        emit_server_timing_element(req, &dst, "request-header", vhttp_time_compute_header_time, max_len);
        emit_server_timing_element(req, &dst, "request-body", vhttp_time_compute_body_time, max_len);
        emit_server_timing_element(req, &dst, "request-total", vhttp_time_compute_request_total_time, max_len);
        emit_server_timing_element(req, &dst, "process", vhttp_time_compute_process_time, max_len);
    }
    if ((req->send_server_timing & vhttp_SEND_SERVER_TIMING_PROXY) != 0) {
        emit_server_timing_element(req, &dst, "proxy.idle", vhttp_time_compute_proxy_idle_time, max_len);
        emit_server_timing_element(req, &dst, "proxy.connect", vhttp_time_compute_proxy_connect_time, max_len);
        emit_server_timing_element(req, &dst, "proxy.request", vhttp_time_compute_proxy_request_time, max_len);
        emit_server_timing_element(req, &dst, "proxy.process", vhttp_time_compute_proxy_process_time, max_len);
    }

#undef LONGEST_STR

    if (uses_trailer)
        vhttp_add_header_by_str(&req->pool, &req->res.headers, vhttp_STRLIT("trailer"), 0, NULL, vhttp_STRLIT("server-timing"));
    if (dst.len != 0)
        vhttp_add_header_by_str(&req->pool, &req->res.headers, vhttp_STRLIT("server-timing"), 0, NULL, dst.base, dst.len);
}

vhttp_iovec_t vhttp_build_server_timing_trailer(vhttp_req_t *req, const char *prefix, size_t prefix_len, const char *suffix,
                                            size_t suffix_len)
{
    vhttp_iovec_t value;

#define LONGEST_STR                                                                                                                \
    ELEMENT_LONGEST_STR("response")                                                                                                \
    DELIMITER ELEMENT_LONGEST_STR("total") DELIMITER ELEMENT_LONGEST_STR("proxy.response")                                         \
        DELIMITER ELEMENT_LONGEST_STR("proxy.total")

    value.base = vhttp_mem_alloc_pool(&req->pool, *value.base, prefix_len + suffix_len + sizeof(LONGEST_STR) - 1);
    value.len = 0;

    if (prefix_len != 0) {
        memcpy(value.base + value.len, prefix, prefix_len);
        value.len += prefix_len;
    }

    vhttp_iovec_t dst = vhttp_iovec_init(value.base + value.len, 0);

    if ((req->send_server_timing & vhttp_SEND_SERVER_TIMING_BASIC) != 0) {
        emit_server_timing_element(req, &dst, "response", vhttp_time_compute_response_time, SIZE_MAX);
        emit_server_timing_element(req, &dst, "total", vhttp_time_compute_total_time, SIZE_MAX);
    }
    if ((req->send_server_timing & vhttp_SEND_SERVER_TIMING_PROXY) != 0) {
        emit_server_timing_element(req, &dst, "proxy.response", vhttp_time_compute_proxy_response_time, SIZE_MAX);
        emit_server_timing_element(req, &dst, "proxy.total", vhttp_time_compute_proxy_total_time, SIZE_MAX);
    }

    if (dst.len == 0)
        return vhttp_iovec_init(NULL, 0);
    value.len += dst.len;

    if (suffix_len != 0) {
        memcpy(value.base + value.len, suffix, suffix_len);
        value.len += suffix_len;
    }

    return value;

#undef LONGEST_STR
}

#undef ELEMENT_LONGEST_STR
#undef DELIMITER

/* h2-14 and h2-16 are kept for backwards compatibility, as they are often used */
#define ALPN_ENTRY(s)                                                                                                              \
    {                                                                                                                              \
        vhttp_STRLIT(s)                                                                                                              \
    }
#define ALPN_PROTOCOLS_CORE ALPN_ENTRY("h2"), ALPN_ENTRY("h2-16"), ALPN_ENTRY("h2-14")
#define NPN_PROTOCOLS_CORE                                                                                                         \
    "\x02"                                                                                                                         \
    "h2"                                                                                                                           \
    "\x05"                                                                                                                         \
    "h2-16"                                                                                                                        \
    "\x05"                                                                                                                         \
    "h2-14"

const vhttp_iovec_t vhttp_http2_alpn_protocols[] = {ALPN_PROTOCOLS_CORE, {NULL}};
const vhttp_iovec_t vhttp_alpn_protocols[] = {ALPN_PROTOCOLS_CORE, ALPN_ENTRY("http/1.1"), {NULL}};

const char vhttp_http2_npn_protocols[] = NPN_PROTOCOLS_CORE;
const char vhttp_npn_protocols[] = NPN_PROTOCOLS_CORE "\x08"
                                                    "http/1.1";

uint64_t vhttp_connection_id = 0;

uint32_t vhttp_cleanup_thread(uint64_t now, vhttp_context_t *ctx_optional)
{
    /* File descriptor cache is cleared fully per event loop and it is sufficient to do so, because:
     * * if the file handler opens one file only once per event loop, then calling open (2) is relatively lightweight compared to
     *   other stuff such as connection establishment, and
     * * if a file is large enough that it is not served in one event loop, the file descriptor remains open within the cache. */
    if (ctx_optional != NULL)
        vhttp_filecache_clear(ctx_optional->filecache);

    /* recycle either fully, or partially if at least 1 second has elasped since previous gc */
    static __thread uint64_t next_gc_at;
    if (now >= next_gc_at) {
        int full = now == 0;
        vhttp_buffer_clear_recycle(full);
        vhttp_socket_clear_recycle(full);
        vhttp_mem_clear_recycle(&vhttp_mem_pool_allocator, full);
        next_gc_at = now + 1000;
    }

    /* if all the recyclers are empty, we can sleep forever; otherwise request to be invoked again within no more than one second */
    if (vhttp_buffer_recycle_is_empty() && vhttp_socket_recycle_is_empty() && vhttp_mem_recycle_is_empty(&vhttp_mem_pool_allocator)) {
        return INT32_MAX;
    } else {
        return 1000;
    }
}
