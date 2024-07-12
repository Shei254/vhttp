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
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/time.h>
#include "vhttp.h"
#include "vhttp/memcached.h"

void vhttp_context_init_pathconf_context(vhttp_context_t *ctx, vhttp_pathconf_t *pathconf)
{
    /* add pathconf to the inited list (or return if already inited) */
    size_t i;
    for (i = 0; i != ctx->_pathconfs_inited.size; ++i)
        if (ctx->_pathconfs_inited.entries[i] == pathconf)
            return;
    vhttp_vector_reserve(NULL, &ctx->_pathconfs_inited, ctx->_pathconfs_inited.size + 1);
    ctx->_pathconfs_inited.entries[ctx->_pathconfs_inited.size++] = pathconf;

#define DOIT(type, list)                                                                                                           \
    do {                                                                                                                           \
        size_t i;                                                                                                                  \
        for (i = 0; i != pathconf->list.size; ++i) {                                                                               \
            type *o = pathconf->list.entries[i];                                                                                   \
            if (o->on_context_init != NULL)                                                                                        \
                o->on_context_init(o, ctx);                                                                                        \
        }                                                                                                                          \
    } while (0)

    DOIT(vhttp_handler_t, handlers);
    DOIT(vhttp_filter_t, _filters);
    DOIT(vhttp_logger_t, _loggers);

#undef DOIT
}

void vhttp_context_dispose_pathconf_context(vhttp_context_t *ctx, vhttp_pathconf_t *pathconf)
{
    /* nullify pathconf in the inited list (or return if already disposed) */
    size_t i;
    for (i = 0; i != ctx->_pathconfs_inited.size; ++i)
        if (ctx->_pathconfs_inited.entries[i] == pathconf)
            break;
    if (i == ctx->_pathconfs_inited.size)
        return;
    ctx->_pathconfs_inited.entries[i] = NULL;

#define DOIT(type, list)                                                                                                           \
    do {                                                                                                                           \
        size_t i;                                                                                                                  \
        for (i = 0; i != pathconf->list.size; ++i) {                                                                               \
            type *o = pathconf->list.entries[i];                                                                                   \
            if (o->on_context_dispose != NULL)                                                                                     \
                o->on_context_dispose(o, ctx);                                                                                     \
        }                                                                                                                          \
    } while (0)

    DOIT(vhttp_handler_t, handlers);
    DOIT(vhttp_filter_t, _filters);
    DOIT(vhttp_logger_t, _loggers);

#undef DOIT
}

void vhttp_context_init(vhttp_context_t *ctx, vhttp_loop_t *loop, vhttp_globalconf_t *config)
{
    size_t i, j;

    assert(config->hosts[0] != NULL);

    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    ctx->globalconf = config;
    ctx->queue = vhttp_multithread_create_queue(loop);
    vhttp_multithread_register_receiver(ctx->queue, &ctx->receivers.hostinfo_getaddr, vhttp_hostinfo_getaddr_receiver);
    ctx->filecache = vhttp_filecache_create(config->filecache.capacity);

    vhttp_linklist_init_anchor(&ctx->_conns.active);
    vhttp_linklist_init_anchor(&ctx->_conns.idle);
    vhttp_linklist_init_anchor(&ctx->_conns.shutdown);
    ctx->proxy.client_ctx.loop = loop;
    ctx->proxy.client_ctx.io_timeout = ctx->globalconf->proxy.io_timeout;
    ctx->proxy.client_ctx.connect_timeout = ctx->globalconf->proxy.connect_timeout;
    ctx->proxy.client_ctx.first_byte_timeout = ctx->globalconf->proxy.first_byte_timeout;
    ctx->proxy.client_ctx.keepalive_timeout = ctx->globalconf->proxy.keepalive_timeout;
    ctx->proxy.client_ctx.getaddr_receiver = &ctx->receivers.hostinfo_getaddr;
    ctx->proxy.client_ctx.http2.latency_optimization = ctx->globalconf->http2.latency_optimization;
    ctx->proxy.client_ctx.max_buffer_size = ctx->globalconf->proxy.max_buffer_size;
    ctx->proxy.client_ctx.http2.max_concurrent_streams = ctx->globalconf->proxy.http2.max_concurrent_streams;
    ctx->proxy.client_ctx.protocol_selector.ratio.http2 = ctx->globalconf->proxy.protocol_ratio.http2;
    ctx->proxy.client_ctx.protocol_selector.ratio.http3 = ctx->globalconf->proxy.protocol_ratio.http3;
    ctx->proxy.connpool.socketpool = &ctx->globalconf->proxy.global_socketpool;
    ctx->proxy.spare_pipes.pipes = vhttp_mem_alloc(sizeof(ctx->proxy.spare_pipes.pipes[0]) * config->proxy.max_spare_pipes);
    vhttp_linklist_init_anchor(&ctx->proxy.connpool.http2.conns);

#ifdef __linux__
    /* pre-fill the pipe cache at context init */
    for (i = 0; i < config->proxy.max_spare_pipes; ++i) {
        if (pipe2(ctx->proxy.spare_pipes.pipes[i], O_NONBLOCK | O_CLOEXEC) != 0) {
            char errbuf[256];
            vhttp_fatal("pipe2(2) failed:%s", vhttp_strerror_r(errno, errbuf, sizeof(errbuf)));
        }
        ctx->proxy.spare_pipes.count++;
    }
#endif

    ctx->_module_configs = vhttp_mem_alloc(sizeof(*ctx->_module_configs) * config->_num_config_slots);
    memset(ctx->_module_configs, 0, sizeof(*ctx->_module_configs) * config->_num_config_slots);

    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mutex);

    vhttp_socketpool_register_loop(&ctx->globalconf->proxy.global_socketpool, loop);

    for (i = 0; config->hosts[i] != NULL; ++i) {
        vhttp_hostconf_t *hostconf = config->hosts[i];
        for (j = 0; j != hostconf->paths.size; ++j) {
            vhttp_pathconf_t *pathconf = hostconf->paths.entries[j];
            vhttp_context_init_pathconf_context(ctx, pathconf);
        }
        vhttp_context_init_pathconf_context(ctx, &hostconf->fallback_path);
    }

    pthread_mutex_unlock(&mutex);
}

void vhttp_context_dispose(vhttp_context_t *ctx)
{
    vhttp_globalconf_t *config = ctx->globalconf;
    size_t i, j;

    for (size_t i = 0; i < ctx->proxy.spare_pipes.count; ++i) {
        close(ctx->proxy.spare_pipes.pipes[i][0]);
        close(ctx->proxy.spare_pipes.pipes[i][1]);
    }
    free(ctx->proxy.spare_pipes.pipes);

    vhttp_socketpool_unregister_loop(&ctx->globalconf->proxy.global_socketpool, ctx->loop);

    for (i = 0; config->hosts[i] != NULL; ++i) {
        vhttp_hostconf_t *hostconf = config->hosts[i];
        for (j = 0; j != hostconf->paths.size; ++j) {
            vhttp_pathconf_t *pathconf = hostconf->paths.entries[j];
            vhttp_context_dispose_pathconf_context(ctx, pathconf);
        }
        vhttp_context_dispose_pathconf_context(ctx, &hostconf->fallback_path);
    }
    free(ctx->_pathconfs_inited.entries);
    free(ctx->_module_configs);
    /* what should we do here? assert(!vhttp_linklist_is_empty(&ctx->http2._conns); */

    vhttp_filecache_destroy(ctx->filecache);
    ctx->filecache = NULL;

    /* clear storage */
    for (i = 0; i != ctx->storage.size; ++i) {
        vhttp_context_storage_item_t *item = ctx->storage.entries + i;
        if (item->dispose != NULL) {
            item->dispose(item->data);
        }
    }
    free(ctx->storage.entries);

    /* TODO assert that the all the getaddrinfo threads are idle */
    vhttp_multithread_unregister_receiver(ctx->queue, &ctx->receivers.hostinfo_getaddr);
    vhttp_multithread_destroy_queue(ctx->queue);

    if (ctx->_timestamp_cache.value != NULL)
        vhttp_mem_release_shared(ctx->_timestamp_cache.value);
}

void vhttp_context_request_shutdown(vhttp_context_t *ctx)
{
    ctx->shutdown_requested = 1;

    vhttp_CONN_LIST_FOREACH(vhttp_conn_t * conn, ({&ctx->_conns.active, &ctx->_conns.idle}), {
        if (conn->callbacks->request_shutdown != NULL) {
            conn->callbacks->request_shutdown(conn);
        }
    });
}

void vhttp_context_update_timestamp_string_cache(vhttp_context_t *ctx)
{
    struct tm gmt;
    if (ctx->_timestamp_cache.value != NULL)
        vhttp_mem_release_shared(ctx->_timestamp_cache.value);
    ctx->_timestamp_cache.value = vhttp_mem_alloc_shared(NULL, sizeof(vhttp_timestamp_string_t), NULL);
    gmtime_r(&ctx->_timestamp_cache.tv_at.tv_sec, &gmt);
    vhttp_time2str_rfc1123(ctx->_timestamp_cache.value->rfc1123, &gmt);
    vhttp_time2str_log(ctx->_timestamp_cache.value->log, ctx->_timestamp_cache.tv_at.tv_sec);
}

void vhttp_context_close_idle_connections(vhttp_context_t *ctx, size_t max_connections_to_close, uint64_t min_age)
{
    if (max_connections_to_close <= 0)
        return;

    size_t closed = ctx->_conns.num_conns.shutdown;

    if (closed >= max_connections_to_close)
        return;

    vhttp_CONN_LIST_FOREACH(vhttp_conn_t * conn, ({&ctx->_conns.idle}), {
        struct timeval now = vhttp_gettimeofday(ctx->loop);
        if (vhttp_timeval_subtract(&conn->connected_at, &now) < (min_age * 1000))
            continue;
        ctx->connection_stats.idle_closed++;
        conn->callbacks->close_idle_connection(conn);
        closed++;
        if (closed == max_connections_to_close)
            return;
    });
}

static size_t *get_connection_state_counter(vhttp_context_t *ctx, vhttp_conn_state_t state)
{
    return ctx->_conns.num_conns.counters + (size_t)state;
}

static void unlink_conn(vhttp_conn_t *conn)
{
    --*get_connection_state_counter(conn->ctx, conn->state);
    vhttp_linklist_unlink(&conn->_conns);
}

static void link_conn(vhttp_conn_t *conn)
{
    switch (conn->state) {
    case vhttp_CONN_STATE_IDLE:
        vhttp_linklist_insert(&conn->ctx->_conns.idle, &conn->_conns);
        break;
    case vhttp_CONN_STATE_ACTIVE:
        vhttp_linklist_insert(&conn->ctx->_conns.active, &conn->_conns);
        break;
    case vhttp_CONN_STATE_SHUTDOWN:
        vhttp_linklist_insert(&conn->ctx->_conns.shutdown, &conn->_conns);
        break;
    }
    ++*get_connection_state_counter(conn->ctx, conn->state);
}

vhttp_conn_t *vhttp_create_connection(size_t sz, vhttp_context_t *ctx, vhttp_hostconf_t **hosts, struct timeval connected_at,
                                  const vhttp_conn_callbacks_t *callbacks)
{
    vhttp_conn_t *conn = (vhttp_conn_t *)vhttp_mem_alloc(sz);

    conn->ctx = ctx;
    conn->hosts = hosts;
    conn->connected_at = connected_at;
#ifdef vhttp_NO_64BIT_ATOMICS
    pthread_mutex_lock(&vhttp_conn_id_mutex);
    conn->id = ++vhttp_connection_id;
    pthread_mutex_unlock(&vhttp_conn_id_mutex);
#else
    conn->id = __sync_add_and_fetch(&vhttp_connection_id, 1);
#endif
    conn->callbacks = callbacks;
    conn->_uuid.is_initialized = 0;

    conn->state = vhttp_CONN_STATE_ACTIVE;
    conn->_conns = (vhttp_linklist_t){};
    link_conn(conn);

    return conn;
}

void vhttp_destroy_connection(vhttp_conn_t *conn)
{
    unlink_conn(conn);
    free(conn);
}

void vhttp_conn_set_state(vhttp_conn_t *conn, vhttp_conn_state_t state)
{
    if (conn->state != state) {
        unlink_conn(conn);
        conn->state = state;
        link_conn(conn);
    }
}
