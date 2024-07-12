/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Tatsuhiro Tsujikawa
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include "vhttp.h"
#include "vhttp/socket.h"

#ifndef IOV_MAX
#define IOV_MAX UIO_MAXIOV
#endif

#define INITIAL_INBUFSZ 8192

struct st_deferred_request_action_t {
    vhttp_timer_t timeout;
    vhttp_req_t *req;
};

struct st_reprocess_request_deferred_t {
    struct st_deferred_request_action_t super;
    vhttp_iovec_t method;
    const vhttp_url_scheme_t *scheme;
    vhttp_iovec_t authority;
    vhttp_iovec_t path;
    vhttp_req_overrides_t *overrides;
    int is_delegated;
};

struct st_send_error_deferred_t {
    vhttp_req_t *req;
    int status;
    const char *reason;
    const char *body;
    int flags;
    vhttp_timer_t _timeout;
};

static void on_deferred_action_dispose(void *_action)
{
    struct st_deferred_request_action_t *action = _action;
    vhttp_timer_unlink(&action->timeout);
}

static struct st_deferred_request_action_t *create_deferred_action(vhttp_req_t *req, size_t sz, vhttp_timer_cb cb)
{
    struct st_deferred_request_action_t *action = vhttp_mem_alloc_shared(&req->pool, sz, on_deferred_action_dispose);
    action->req = req;
    vhttp_timer_init(&action->timeout, cb);
    vhttp_timer_link(req->conn->ctx->loop, 0, &action->timeout);
    return action;
}

static vhttp_hostconf_t *find_hostconf(vhttp_hostconf_t **hostconfs, vhttp_iovec_t authority, uint16_t default_port,
                                     vhttp_iovec_t *wildcard_match)
{
    vhttp_iovec_t hostname;
    uint16_t port;
    char *hostname_lc;

    /* safe-guard for alloca */
    if (authority.len >= 65536)
        return NULL;

    /* extract the specified hostname and port */
    if (vhttp_url_parse_hostport(authority.base, authority.len, &hostname, &port) == NULL)
        return NULL;
    if (port == 65535)
        port = default_port;

    /* convert supplied hostname to lower-case */
    hostname_lc = alloca(hostname.len);
    vhttp_strcopytolower(hostname_lc, hostname.base, hostname.len);

    do {
        vhttp_hostconf_t *hostconf = *hostconfs;
        if (hostconf->authority.port == port || (hostconf->authority.port == 65535 && port == default_port)) {
            if (hostconf->authority.host.base[0] == '*') {
                /* matching against "*.foo.bar" */
                size_t cmplen = hostconf->authority.host.len - 1;
                if (cmplen < hostname.len &&
                    memcmp(hostconf->authority.host.base + 1, hostname_lc + hostname.len - cmplen, cmplen) == 0) {
                    *wildcard_match = vhttp_iovec_init(hostname.base, hostname.len - cmplen);
                    return hostconf;
                }
            } else {
                /* exact match */
                if (vhttp_memis(hostconf->authority.host.base, hostconf->authority.host.len, hostname_lc, hostname.len))
                    return hostconf;
            }
        }
    } while (*++hostconfs != NULL);

    return NULL;
}

static vhttp_hostconf_t *find_default_hostconf(vhttp_hostconf_t **hostconfs)
{
    vhttp_hostconf_t *fallback_host = hostconfs[0]->global->fallback_host;

    do {
        vhttp_hostconf_t *hostconf = *hostconfs;
        if (!hostconf->strict_match)
            return hostconf;
    } while (*++hostconfs != NULL);

    return fallback_host;
}

vhttp_hostconf_t *vhttp_req_setup(vhttp_req_t *req)
{
    vhttp_context_t *ctx = req->conn->ctx;
    vhttp_hostconf_t *hostconf;

    req->processed_at = vhttp_get_timestamp(ctx, &req->pool);

    /* find the host context (or use the default if authority is missing or is of zero-length) */
    if (req->input.authority.len != 0) {
        if (req->conn->hosts[1] == NULL ||
            (hostconf = find_hostconf(req->conn->hosts, req->input.authority, req->input.scheme->default_port,
                                      &req->authority_wildcard_match)) == NULL)
            hostconf = find_default_hostconf(req->conn->hosts);
    } else {
        hostconf = find_default_hostconf(req->conn->hosts);
        req->input.authority = hostconf->authority.hostport;
    }

    req->scheme = req->input.scheme;
    req->method = req->input.method;
    req->authority = req->input.authority;
    req->path = req->input.path;
    req->path_normalized =
        vhttp_url_normalize_path(&req->pool, req->input.path.base, req->input.path.len, &req->query_at, &req->norm_indexes);
    req->input.query_at = req->query_at; /* we can do this since input.path == path */

    return hostconf;
}

static void call_handlers(vhttp_req_t *req, vhttp_handler_t **handler)
{
    vhttp_handler_t **end = req->pathconf->handlers.entries + req->pathconf->handlers.size;

    for (; handler != end; ++handler) {
        req->handler = *handler;
        if ((*handler)->on_req(*handler, req) == 0)
            return;
    }

    vhttp_send_error_404(req, "File Not Found", "not found", 0);
}

static void setup_pathconf(vhttp_req_t *req, vhttp_hostconf_t *hostconf)
{
    vhttp_pathconf_t *selected_pathconf = &hostconf->fallback_path;
    size_t i;

    /* setup pathconf, or redirect to "path/" */
    for (i = 0; i != hostconf->paths.size; ++i) {
        vhttp_pathconf_t *candidate = hostconf->paths.entries[i];
        if (req->path_normalized.len >= candidate->path.len &&
            memcmp(req->path_normalized.base, candidate->path.base, candidate->path.len) == 0 &&
            (candidate->path.base[candidate->path.len - 1] == '/' || req->path_normalized.len == candidate->path.len ||
             req->path_normalized.base[candidate->path.len] == '/')) {
            selected_pathconf = candidate;
            break;
        }
    }
    vhttp_req_bind_conf(req, hostconf, selected_pathconf);
}

static void deferred_proceed_cb(vhttp_timer_t *entry)
{
    vhttp_req_t *req = vhttp_STRUCT_FROM_MEMBER(vhttp_req_t, _timeout_entry, entry);
    vhttp_proceed_response(req);
}

static void close_generator_and_filters(vhttp_req_t *req)
{
    /* close the generator if it is still open */
    if (req->_generator != NULL) {
        /* close generator */
        if (req->_generator->stop != NULL)
            req->_generator->stop(req->_generator, req);
        req->_generator = NULL;
    }
    /* close the ostreams still open */
    while (req->_ostr_top->next != NULL) {
        if (req->_ostr_top->stop != NULL)
            req->_ostr_top->stop(req->_ostr_top, req);
        req->_ostr_top = req->_ostr_top->next;
    }
}

static void reset_response(vhttp_req_t *req)
{
    req->res = (vhttp_res_t){0, NULL, SIZE_MAX};
    req->res.reason = "OK";
    req->_next_filter_index = 0;
    req->bytes_sent = 0;
}

static void retain_original_response(vhttp_req_t *req)
{
    if (req->res.original.status != 0)
        return;

    req->res.original.status = req->res.status;
    vhttp_vector_reserve(&req->pool, &req->res.original.headers, req->res.headers.size);
    vhttp_memcpy(req->res.original.headers.entries, req->res.headers.entries,
               sizeof(req->res.headers.entries[0]) * req->res.headers.size);
    req->res.original.headers.size = req->res.headers.size;
}

void vhttp_write_error_log(vhttp_iovec_t prefix, vhttp_iovec_t msg)
{
    /* use writev(2) to emit error atomically */
    struct iovec vecs[] = {{prefix.base, prefix.len}, {msg.base, msg.len}, {"\n", 1}};
    vhttp_BUILD_ASSERT(sizeof(vecs) / sizeof(vecs[0]) <= IOV_MAX);
    writev(2, vecs, sizeof(vecs) / sizeof(vecs[0]));
}

static void on_default_error_callback(void *data, vhttp_iovec_t prefix, vhttp_iovec_t msg)
{
    vhttp_req_t *req = (void *)data;
    if (req->error_logs == NULL)
        vhttp_buffer_init(&req->error_logs, &vhttp_socket_buffer_prototype);
    vhttp_buffer_append(&req->error_logs, prefix.base, prefix.len);
    vhttp_buffer_append(&req->error_logs, msg.base, msg.len);

    if (req->pathconf->error_log.emit_request_errors) {
        vhttp_write_error_log(prefix, msg);
    }
}

void vhttp_init_request(vhttp_req_t *req, vhttp_conn_t *conn, vhttp_req_t *src)
{
    /* clear all memory (expect memory pool, since it is large) */
    memset(req, 0, offsetof(vhttp_req_t, pool));

    /* init memory pool (before others, since it may be used) */
    vhttp_mem_init_pool(&req->pool);

    /* init properties that should be initialized to non-zero */
    req->conn = conn;
    req->_timeout_entry.cb = deferred_proceed_cb;
    req->res.reason = "OK"; /* default to "OK" regardless of the status value, it's not important after all (never sent in HTTP2) */
    req->res.content_length = SIZE_MAX;
    req->preferred_chunk_size = SIZE_MAX;
    req->content_length = SIZE_MAX;
    req->remaining_delegations = conn == NULL ? 0 : conn->ctx->globalconf->max_delegations;
    req->remaining_reprocesses = conn == NULL ? 0 : conn->ctx->globalconf->max_reprocesses;
    req->error_log_delegate.cb = on_default_error_callback;
    req->error_log_delegate.data = req;

    if (src != NULL) {
        size_t i;
#define COPY(buf)                                                                                                                  \
    do {                                                                                                                           \
        req->buf.base = vhttp_mem_alloc_pool(&req->pool, char, src->buf.len);                                                        \
        memcpy(req->buf.base, src->buf.base, src->buf.len);                                                                        \
        req->buf.len = src->buf.len;                                                                                               \
    } while (0)
        COPY(input.authority);
        COPY(input.method);
        COPY(input.path);
        req->input.scheme = src->input.scheme;
        req->version = src->version;
        req->entity = src->entity;
        req->http1_is_persistent = src->http1_is_persistent;
        req->timestamps = src->timestamps;
        if (src->upgrade.base != NULL) {
            COPY(upgrade);
        } else {
            req->upgrade.base = NULL;
            req->upgrade.len = 0;
        }
#undef COPY
        vhttp_vector_reserve(&req->pool, &req->headers, src->headers.size);
        req->headers.size = src->headers.size;
        for (i = 0; i != src->headers.size; ++i) {
            vhttp_header_t *dst_header = req->headers.entries + i, *src_header = src->headers.entries + i;
            if (vhttp_iovec_is_token(src_header->name)) {
                dst_header->name = src_header->name;
            } else {
                dst_header->name = vhttp_mem_alloc_pool(&req->pool, *dst_header->name, 1);
                *dst_header->name = vhttp_strdup(&req->pool, src_header->name->base, src_header->name->len);
            }
            dst_header->value = vhttp_strdup(&req->pool, src_header->value.base, src_header->value.len);
            dst_header->flags = src_header->flags;
            if (!src_header->orig_name)
                dst_header->orig_name = NULL;
            else
                dst_header->orig_name = vhttp_strdup(&req->pool, src_header->orig_name, src_header->name->len).base;
        }
        if (src->env.size != 0) {
            vhttp_vector_reserve(&req->pool, &req->env, src->env.size);
            req->env.size = src->env.size;
            for (i = 0; i != req->env.size; ++i)
                req->env.entries[i] = vhttp_strdup(&req->pool, src->env.entries[i].base, src->env.entries[i].len);
        }
    }
}

void vhttp_dispose_request(vhttp_req_t *req)
{
    close_generator_and_filters(req);

    vhttp_timer_unlink(&req->_timeout_entry);

    if (req->pathconf != NULL && req->num_loggers != 0) {
        for (vhttp_logger_t **logger = req->loggers, **end = logger + req->num_loggers; logger != end; ++logger) {
            (*logger)->log_access((*logger), req);
        }
    }

    if (req->error_logs != NULL)
        vhttp_buffer_dispose(&req->error_logs);

    vhttp_mem_clear_pool(&req->pool);
}

int vhttp_req_validate_pseudo_headers(vhttp_req_t *req)
{
    if (vhttp_memis(req->input.method.base, req->input.method.len, vhttp_STRLIT("CONNECT-UDP"))) {
        /* The draft requires "masque" in `:scheme` but we need to support clients that put "https" there instead. */
        if (req->input.scheme != &vhttp_URL_SCHEME_MASQUE && req->input.scheme != &vhttp_URL_SCHEME_HTTPS)
            return 0;
        if (!vhttp_memis(req->input.path.base, req->input.path.len, vhttp_STRLIT("/")))
            return 0;
    } else {
        if (req->input.scheme == &vhttp_URL_SCHEME_MASQUE)
            return 0;
    }

    return 1;
}

vhttp_handler_t *vhttp_get_first_handler(vhttp_req_t *req)
{
    vhttp_hostconf_t *hostconf = vhttp_req_setup(req);
    setup_pathconf(req, hostconf);
    return req->pathconf->handlers.size != 0 ? req->pathconf->handlers.entries[0] : NULL;
}

void vhttp_process_request(vhttp_req_t *req)
{
    assert(!req->process_called);
    req->process_called = 1;

    if (req->pathconf == NULL) {
        vhttp_hostconf_t *hostconf = vhttp_req_setup(req);
        setup_pathconf(req, hostconf);
    }
    call_handlers(req, req->pathconf->handlers.entries);
}

void vhttp_delegate_request(vhttp_req_t *req)
{
    vhttp_handler_t **handler = req->pathconf->handlers.entries, **end = handler + req->pathconf->handlers.size;
    for (;; ++handler) {
        assert(handler != end);
        if (*handler == req->handler)
            break;
    }
    ++handler;
    call_handlers(req, handler);
}

static void on_delegate_request_cb(vhttp_timer_t *entry)
{
    struct st_deferred_request_action_t *args = vhttp_STRUCT_FROM_MEMBER(struct st_deferred_request_action_t, timeout, entry);
    vhttp_delegate_request(args->req);
}

void vhttp_delegate_request_deferred(vhttp_req_t *req)
{
    create_deferred_action(req, sizeof(struct st_deferred_request_action_t), on_delegate_request_cb);
}

static void process_resolved_request(vhttp_req_t *req, vhttp_hostconf_t **hosts)
{
    vhttp_hostconf_t *hostconf;
    if (req->overrides == NULL &&
        (hostconf = find_hostconf(hosts, req->authority, req->scheme->default_port, &req->authority_wildcard_match)) != NULL) {
        setup_pathconf(req, hostconf);
        call_handlers(req, req->pathconf->handlers.entries);
        return;
    }

    /* uses the current pathconf, in other words, proxy uses the previous pathconf for building filters */
    vhttp__proxy_process_request(req);
}

void vhttp_reprocess_request(vhttp_req_t *req, vhttp_iovec_t method, const vhttp_url_scheme_t *scheme, vhttp_iovec_t authority,
                           vhttp_iovec_t path, vhttp_req_overrides_t *overrides, int is_delegated)
{
    retain_original_response(req);

    /* close generators and filters that are already running */
    close_generator_and_filters(req);

    /* setup the request/response parameters */
    req->handler = NULL;
    req->method = method;
    req->scheme = scheme;
    req->authority = authority;
    req->path = path;
    req->path_normalized = vhttp_url_normalize_path(&req->pool, req->path.base, req->path.len, &req->query_at, &req->norm_indexes);
    req->authority_wildcard_match = vhttp_iovec_init(NULL, 0);
    req->overrides = overrides;
    req->res_is_delegated |= is_delegated;
    req->reprocess_if_too_early = 0;
    reset_response(req);

    /* check the delegation (or reprocess) counter */
    if (req->res_is_delegated) {
        if (req->remaining_delegations == 0) {
            /* TODO log */
            vhttp_send_error_502(req, "Gateway Error", "too many internal delegations", 0);
            return;
        }
        --req->remaining_delegations;
    } else {
        if (req->remaining_reprocesses == 0) {
            /* TODO log */
            vhttp_send_error_502(req, "Gateway Error", "too many internal reprocesses", 0);
            return;
        }
        --req->remaining_reprocesses;
    }

    process_resolved_request(req, req->conn->ctx->globalconf->hosts);
}

static void on_reprocess_request_cb(vhttp_timer_t *entry)
{
    struct st_reprocess_request_deferred_t *args =
        vhttp_STRUCT_FROM_MEMBER(struct st_reprocess_request_deferred_t, super.timeout, entry);
    vhttp_reprocess_request(args->super.req, args->method, args->scheme, args->authority, args->path, args->overrides,
                          args->is_delegated);
}

void vhttp_reprocess_request_deferred(vhttp_req_t *req, vhttp_iovec_t method, const vhttp_url_scheme_t *scheme, vhttp_iovec_t authority,
                                    vhttp_iovec_t path, vhttp_req_overrides_t *overrides, int is_delegated)
{
    struct st_reprocess_request_deferred_t *args =
        (struct st_reprocess_request_deferred_t *)create_deferred_action(req, sizeof(*args), on_reprocess_request_cb);
    args->method = method;
    args->scheme = scheme;
    args->authority = authority;
    args->path = path;
    args->overrides = overrides;
    args->is_delegated = is_delegated;
}

void vhttp_replay_request(vhttp_req_t *req)
{
    close_generator_and_filters(req);
    reset_response(req);

    if (req->handler != NULL) {
        vhttp_handler_t **handler = req->pathconf->handlers.entries, **end = handler + req->pathconf->handlers.size;
        for (;; ++handler) {
            assert(handler != end);
            if (*handler == req->handler)
                break;
        }
        call_handlers(req, handler);
    } else {
        process_resolved_request(req, req->conn->hosts);
    }
}

static void on_replay_request_cb(vhttp_timer_t *entry)
{
    struct st_deferred_request_action_t *args = vhttp_STRUCT_FROM_MEMBER(struct st_deferred_request_action_t, timeout, entry);
    vhttp_replay_request(args->req);
}

void vhttp_replay_request_deferred(vhttp_req_t *req)
{
    create_deferred_action(req, sizeof(struct st_deferred_request_action_t), on_replay_request_cb);
}

void vhttp_start_response(vhttp_req_t *req, vhttp_generator_t *generator)
{
    retain_original_response(req);

    /* set generator */
    assert(req->_generator == NULL);
    req->_generator = generator;

    if (req->is_tunnel_req && (req->res.status == 101 || req->res.status == 200)) {
        /* a tunnel has been established; forward response as is */
    } else {
        /* setup response filters */
        if (req->prefilters != NULL) {
            req->prefilters->on_setup_ostream(req->prefilters, req, &req->_ostr_top);
        } else {
            vhttp_setup_next_ostream(req, &req->_ostr_top);
        }
    }
}

static void do_sendvec(vhttp_req_t *req, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_send_state_t state)
{
    assert(req->_generator != NULL);

    if (!vhttp_send_state_is_in_progress(state))
        req->_generator = NULL;

    req->_ostr_top->do_send(req->_ostr_top, req, bufs, bufcnt, state);
}

void vhttp_send(vhttp_req_t *req, vhttp_iovec_t *bufs, size_t bufcnt, vhttp_send_state_t state)
{
    vhttp_sendvec_t *vecs = alloca(sizeof(*vecs) * bufcnt);
    size_t i;

    for (i = 0; i != bufcnt; ++i)
        vhttp_sendvec_init_raw(vecs + i, bufs[i].base, bufs[i].len);

    do_sendvec(req, vecs, bufcnt, state);
}

void vhttp_sendvec(vhttp_req_t *req, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_send_state_t state)
{
    assert(bufcnt == 0 || (bufs[0].callbacks->read_ == &vhttp_sendvec_read_raw || bufcnt == 1));
    do_sendvec(req, bufs, bufcnt, state);
}

vhttp_req_prefilter_t *vhttp_add_prefilter(vhttp_req_t *req, size_t alignment, size_t sz)
{
    vhttp_req_prefilter_t *prefilter = vhttp_mem_alloc_pool_aligned(&req->pool, alignment, sz);
    prefilter->next = req->prefilters;
    req->prefilters = prefilter;
    return prefilter;
}

vhttp_ostream_t *vhttp_add_ostream(vhttp_req_t *req, size_t alignment, size_t sz, vhttp_ostream_t **slot)
{
    vhttp_ostream_t *ostr = vhttp_mem_alloc_pool_aligned(&req->pool, alignment, sz);
    ostr->next = *slot;
    ostr->do_send = NULL;
    ostr->stop = NULL;
    ostr->send_informational = NULL;

    *slot = ostr;

    return ostr;
}

void vhttp_req_apply_env(vhttp_req_t *req, vhttp_envconf_t *env)
{
    size_t i;

    if (env->parent != NULL)
        vhttp_req_apply_env(req, env->parent);
    for (i = 0; i != env->unsets.size; ++i)
        vhttp_req_unsetenv(req, env->unsets.entries[i].base, env->unsets.entries[i].len);
    for (i = 0; i != env->sets.size; i += 2)
        *vhttp_req_getenv(req, env->sets.entries[i].base, env->sets.entries[i].len, 1) = env->sets.entries[i + 1];
}

void vhttp_req_bind_conf(vhttp_req_t *req, vhttp_hostconf_t *hostconf, vhttp_pathconf_t *pathconf)
{
    req->hostconf = hostconf;
    req->pathconf = pathconf;

    /* copy filters and loggers */
    req->filters = pathconf->_filters.entries;
    req->num_filters = pathconf->_filters.size;
    req->loggers = pathconf->_loggers.entries;
    req->num_loggers = pathconf->_loggers.size;

    if (pathconf->env != NULL)
        vhttp_req_apply_env(req, pathconf->env);
}

void vhttp_proceed_response_deferred(vhttp_req_t *req)
{
    vhttp_timer_link(req->conn->ctx->loop, 0, &req->_timeout_entry);
}

void vhttp_ostream_send_next(vhttp_ostream_t *ostream, vhttp_req_t *req, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_send_state_t state)
{
    if (!vhttp_send_state_is_in_progress(state)) {
        assert(req->_ostr_top == ostream);
        req->_ostr_top = ostream->next;
    }
    ostream->next->do_send(ostream->next, req, bufs, bufcnt, state);
}

void vhttp_req_fill_mime_attributes(vhttp_req_t *req)
{
    ssize_t content_type_index;
    vhttp_mimemap_type_t *mime;

    if (req->res.mime_attr != NULL)
        return;

    if ((content_type_index = vhttp_find_header(&req->res.headers, vhttp_TOKEN_CONTENT_TYPE, -1)) != -1 &&
        (mime = vhttp_mimemap_get_type_by_mimetype(req->pathconf->mimemap, req->res.headers.entries[content_type_index].value, 0)) !=
            NULL)
        req->res.mime_attr = &mime->data.attr;
    else
        req->res.mime_attr = &vhttp_mime_attributes_as_is;
}

void vhttp_send_inline(vhttp_req_t *req, const char *body, size_t len)
{
    static vhttp_generator_t generator = {NULL, NULL};

    vhttp_iovec_t buf = vhttp_strdup(&req->pool, body, len);
    /* the function intentionally does not set the content length, since it may be used for generating 304 response, etc. */
    /* req->res.content_length = buf.len; */

    vhttp_start_response(req, &generator);

    if (vhttp_memis(req->input.method.base, req->input.method.len, vhttp_STRLIT("HEAD")))
        vhttp_send(req, NULL, 0, vhttp_SEND_STATE_FINAL);
    else
        vhttp_send(req, &buf, 1, vhttp_SEND_STATE_FINAL);
}

void vhttp_send_error_generic(vhttp_req_t *req, int status, const char *reason, const char *body, int flags)
{
    if (req->pathconf == NULL) {
        vhttp_hostconf_t *hostconf = vhttp_req_setup(req);
        vhttp_req_bind_conf(req, hostconf, &hostconf->fallback_path);
    }

    /* If the request is broken or incomplete, do not apply filters, as it would be dangerous to do so. Legitimate clients would not
     * send broken requests, so we do not need to decorate error responses using errordoc handler or anything else. */
    if ((flags & vhttp_SEND_ERROR_BROKEN_REQUEST) != 0)
        req->_next_filter_index = SIZE_MAX;

    if ((flags & vhttp_SEND_ERROR_HTTP1_CLOSE_CONNECTION) != 0)
        req->http1_is_persistent = 0;

    req->res.status = status;
    req->res.reason = reason;
    req->res.content_length = strlen(body);

    if ((flags & vhttp_SEND_ERROR_KEEP_HEADERS) == 0)
        memset(&req->res.headers, 0, sizeof(req->res.headers));

    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CONTENT_TYPE, NULL, vhttp_STRLIT("text/plain; charset=utf-8"));

    vhttp_send_inline(req, body, SIZE_MAX);
}

#define DECL_SEND_ERROR_DEFERRED(status_)                                                                                          \
    static void send_error_deferred_cb_##status_(vhttp_timer_t *entry)                                                               \
    {                                                                                                                              \
        struct st_send_error_deferred_t *args = vhttp_STRUCT_FROM_MEMBER(struct st_send_error_deferred_t, _timeout, entry);          \
        reset_response(args->req);                                                                                                 \
        args->req->conn->ctx->emitted_error_status[vhttp_STATUS_ERROR_##status_]++;                                                  \
        vhttp_send_error_generic(args->req, args->status, args->reason, args->body, args->flags);                                    \
    }                                                                                                                              \
                                                                                                                                   \
    static void vhttp_send_error_deferred_##status_(vhttp_req_t *req, const char *reason, const char *body, int flags)                 \
    {                                                                                                                              \
        struct st_send_error_deferred_t *args = vhttp_mem_alloc_pool(&req->pool, *args, 1);                                          \
        *args = (struct st_send_error_deferred_t){req, status_, reason, body, flags};                                              \
        vhttp_timer_init(&args->_timeout, send_error_deferred_cb_##status_);                                                         \
        vhttp_timer_link(req->conn->ctx->loop, 0, &args->_timeout);                                                                  \
    }

DECL_SEND_ERROR_DEFERRED(502)

#undef DECL_SEND_ERROR_DEFERRED

static size_t append_with_limit(char *dst, vhttp_iovec_t input, size_t limit)
{
    if (input.len < limit) {
        memcpy(dst, input.base, input.len);
        return input.len;
    } else {
        memcpy(dst, input.base, (limit - 3));
        memcpy(dst + (limit - 3), "...", 3);
        return limit;
    }
}

void vhttp_req_log_error(vhttp_req_t *req, const char *module, const char *fmt, ...)
{
#define INITIAL_BUF_SIZE 256

    char *errbuf = vhttp_mem_alloc_pool(&req->pool, char, INITIAL_BUF_SIZE);
    int errlen;
    va_list args;

    va_start(args, fmt);
    errlen = vsnprintf(errbuf, INITIAL_BUF_SIZE, fmt, args);
    va_end(args);

    if (errlen >= INITIAL_BUF_SIZE) {
        errbuf = vhttp_mem_alloc_pool(&req->pool, char, errlen + 1);
        va_start(args, fmt);
        errlen = vsnprintf(errbuf, errlen + 1, fmt, args);
        va_end(args);
    }
    vhttp_iovec_t msg = vhttp_iovec_init(errbuf, errlen);

#undef INITIAL_BUF_SIZE

    /* build prefix */
    char *pbuf = vhttp_mem_alloc_pool(&req->pool, char, sizeof("[] in request::") + strlen(module) + 64 + 32);
    char *p = pbuf;
    p += sprintf(p, "[%s] in request:", module);
    p += append_with_limit(p, req->authority, 64);
    p += append_with_limit(p, req->path, 32);
    *p++ = ':';
    vhttp_iovec_t prefix = vhttp_iovec_init(pbuf, p - pbuf);

    /* run error callback (save and emit the log if needed) */
    req->error_log_delegate.cb(req->error_log_delegate.data, prefix, msg);
}

void vhttp_send_redirect(vhttp_req_t *req, int status, const char *reason, const char *url, size_t url_len)
{
    if (req->res_is_delegated) {
        vhttp_iovec_t method = vhttp_get_redirect_method(req->method, status);
        vhttp_send_redirect_internal(req, method, url, url_len, 0);
        return;
    }

    static vhttp_generator_t generator = {NULL, NULL};
    static const vhttp_iovec_t body_prefix = {vhttp_STRLIT("<!DOCTYPE html><TITLE>Moved</TITLE><P>The document has moved <A HREF=\"")};
    static const vhttp_iovec_t body_suffix = {vhttp_STRLIT("\">here</A>")};

    /* build and send response */
    vhttp_iovec_t bufs[3];
    size_t bufcnt;
    if (vhttp_memis(req->input.method.base, req->input.method.len, vhttp_STRLIT("HEAD"))) {
        req->res.content_length = SIZE_MAX;
        bufcnt = 0;
    } else {
        bufs[0] = body_prefix;
        bufs[1] = vhttp_htmlescape(&req->pool, url, url_len);
        bufs[2] = body_suffix;
        bufcnt = 3;
        req->res.content_length = body_prefix.len + bufs[1].len + body_suffix.len;
    }
    req->res.status = status;
    req->res.reason = reason;
    req->res.headers = (vhttp_headers_t){NULL};
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_LOCATION, NULL, url, url_len);
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CONTENT_TYPE, NULL, vhttp_STRLIT("text/html; charset=utf-8"));
    vhttp_start_response(req, &generator);
    vhttp_send(req, bufs, bufcnt, vhttp_SEND_STATE_FINAL);
}

void vhttp_send_redirect_internal(vhttp_req_t *req, vhttp_iovec_t method, const char *url_str, size_t url_len, int preserve_overrides)
{
    vhttp_url_t url;

    /* parse the location URL */
    if (vhttp_url_parse_relative(&req->pool, url_str, url_len, &url) != 0) {
        /* TODO log vhttp_error_printf("[proxy] cannot handle location header: %.*s\n", (int)url_len, url); */
        vhttp_send_error_deferred_502(req, "Gateway Error", "internal error", 0);
        return;
    }
    /* convert the location to absolute (while creating copies of the values passed to the deferred call) */
    if (url.scheme == NULL)
        url.scheme = req->scheme;
    if (url.authority.base == NULL) {
        if (req->hostconf != NULL)
            url.authority = req->hostconf->authority.hostport;
        else
            url.authority = req->authority;
    } else {
        if (vhttp_lcstris(url.authority.base, url.authority.len, req->authority.base, req->authority.len)) {
            url.authority = req->authority;
        } else {
            url.authority = vhttp_strdup(&req->pool, url.authority.base, url.authority.len);
            preserve_overrides = 0;
        }
    }
    vhttp_iovec_t base_path = req->path;
    vhttp_url_resolve_path(&base_path, &url.path);
    url.path = vhttp_concat(&req->pool, base_path, url.path);

    vhttp_reprocess_request_deferred(req, method, url.scheme, url.authority, url.path, preserve_overrides ? req->overrides : NULL, 1);
}

vhttp_iovec_t vhttp_get_redirect_method(vhttp_iovec_t method, int status)
{
    if (vhttp_memis(method.base, method.len, vhttp_STRLIT("POST")) && !(status == 307 || status == 308))
        method = vhttp_iovec_init(vhttp_STRLIT("GET"));
    return method;
}

static void do_push_path(void *_req, const char *path, size_t path_len, int is_critical)
{
    vhttp_req_t *req = _req;

    if (req->conn->callbacks->push_path != NULL)
        req->conn->callbacks->push_path(req, path, path_len, is_critical);
}

vhttp_iovec_t vhttp_push_path_in_link_header(vhttp_req_t *req, const char *value, size_t value_len)
{
    vhttp_iovec_t ret = vhttp_iovec_init(value, value_len);

    vhttp_extract_push_path_from_link_header(&req->pool, value, value_len, req->path_normalized, req->input.scheme,
                                           req->input.authority, req->res_is_delegated ? req->scheme : NULL,
                                           req->res_is_delegated ? &req->authority : NULL, do_push_path, req, &ret,
                                           req->hostconf->http2.allow_cross_origin_push);

    return ret;
}

void vhttp_resp_add_date_header(vhttp_req_t *req)
{
    vhttp_timestamp_t ts = vhttp_get_timestamp(req->conn->ctx, &req->pool);
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_DATE, NULL, ts.str->rfc1123, strlen(ts.str->rfc1123));
}

void vhttp_send_informational(vhttp_req_t *req)
{
    /* 1xx must be sent before vhttp_start_response is called*/
    assert(req->_generator == NULL);
    assert(req->_ostr_top->next == NULL);
    assert(100 <= req->res.status && req->res.status <= 199 && req->res.status != 101);

    if (req->_ostr_top->send_informational == NULL)
        goto Clear;

    size_t index;
    if ((index = vhttp_find_header(&req->headers, vhttp_TOKEN_NO_EARLY_HINTS, -1)) != -1) {
        vhttp_iovec_t value = req->headers.entries[index].value;
        if (value.len == 1 && value.base[0] == '1')
            goto Clear;
    }

    int i = 0;
    for (i = 0; i != req->num_filters; ++i) {
        vhttp_filter_t *filter = req->filters[i];
        if (filter->on_informational != NULL)
            filter->on_informational(filter, req);
    }

    if (req->res.status == 103 && req->res.headers.size == 0)
        goto Clear;

    req->_ostr_top->send_informational(req->_ostr_top, req);

Clear:
    /* clear status and headers */
    req->res.status = 0;
    req->res.headers = (vhttp_headers_t){NULL, 0, 0};
}

int vhttp_req_resolve_internal_redirect_url(vhttp_req_t *req, vhttp_iovec_t dest, vhttp_url_t *resolved)
{
    vhttp_url_t input;

    /* resolve the URL */
    if (vhttp_url_parse_relative(&req->pool, dest.base, dest.len, &input) != 0) {
        return -1;
    }
    if (input.scheme != NULL && input.authority.base != NULL) {
        *resolved = input;
    } else {
        vhttp_url_t base;
        /* we MUST to set authority to that of hostconf, or internal redirect might create a TCP connection */
        if (vhttp_url_init(&base, req->scheme, req->hostconf->authority.hostport, req->path) != 0) {
            return -1;
        }
        vhttp_url_resolve(&req->pool, &base, &input, resolved);
    }

    return 0;
}
