/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd.
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
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/udp.h>
#include "vhttp.h"
#include "vhttp/configurator.h"
#include "vhttp/http1.h"
#include "vhttp/http2.h"
#include "vhttp/http3_server.h"
#include "vhttp/version.h"

static vhttp_hostconf_t *create_hostconf(vhttp_globalconf_t *globalconf)
{
    vhttp_hostconf_t *hostconf = vhttp_mem_alloc(sizeof(*hostconf));
    *hostconf = (vhttp_hostconf_t){globalconf};
    hostconf->http2.push_preload = 1; /* enabled by default */
    vhttp_config_init_pathconf(&hostconf->fallback_path, globalconf, NULL, globalconf->mimemap);
    hostconf->mimemap = globalconf->mimemap;
    vhttp_mem_addref_shared(hostconf->mimemap);
    return hostconf;
}

static void destroy_hostconf(vhttp_hostconf_t *hostconf)
{
    size_t i;

    if (hostconf->authority.hostport.base != hostconf->authority.host.base)
        free(hostconf->authority.hostport.base);
    free(hostconf->authority.host.base);
    for (i = 0; i != hostconf->paths.size; ++i) {
        vhttp_pathconf_t *pathconf = hostconf->paths.entries[i];
        vhttp_config_dispose_pathconf(pathconf);
        free(pathconf);
    }
    free(hostconf->paths.entries);
    vhttp_config_dispose_pathconf(&hostconf->fallback_path);
    vhttp_mem_release_shared(hostconf->mimemap);

    free(hostconf);
}

static void on_dispose_envconf(void *_envconf)
{
    vhttp_envconf_t *envconf = _envconf;
    size_t i;

    if (envconf->parent != NULL)
        vhttp_mem_release_shared(envconf->parent);

    for (i = 0; i != envconf->unsets.size; ++i)
        vhttp_mem_release_shared(envconf->unsets.entries[i].base);
    free(envconf->unsets.entries);
    for (i = 0; i != envconf->sets.size; ++i)
        vhttp_mem_release_shared(envconf->sets.entries[i].base);
    free(envconf->sets.entries);
}

vhttp_envconf_t *vhttp_config_create_envconf(vhttp_envconf_t *parent)
{
    vhttp_envconf_t *envconf = vhttp_mem_alloc_shared(NULL, sizeof(*envconf), on_dispose_envconf);
    *envconf = (vhttp_envconf_t){NULL};

    if (parent != NULL) {
        envconf->parent = parent;
        vhttp_mem_addref_shared(parent);
    }
    return envconf;
}

void vhttp_config_setenv(vhttp_envconf_t *envconf, const char *name, const char *value)
{
    size_t name_len = strlen(name), i;
    vhttp_iovec_t *value_slot;

    /* remove from the list of unsets */
    for (i = 0; i != envconf->unsets.size; ++i) {
        if (vhttp_memis(envconf->unsets.entries[i].base, envconf->unsets.entries[i].len, name, name_len)) {
            vhttp_mem_release_shared(envconf->unsets.entries[i].base);
            vhttp_vector_erase(&envconf->unsets, i);
            break;
        }
    }
    /* find the slot */
    for (i = 0; i != envconf->sets.size; i += 2) {
        if (vhttp_memis(envconf->sets.entries[i].base, envconf->sets.entries[i].len, name, name_len)) {
            value_slot = envconf->sets.entries + i + 1;
            vhttp_mem_release_shared(value_slot->base);
            goto SetValue;
        }
    }
    /* name not found in existing sets */
    vhttp_vector_reserve(NULL, &envconf->sets, envconf->sets.size + 2);
    envconf->sets.entries[envconf->sets.size++] = vhttp_strdup_shared(NULL, name, name_len);
    value_slot = envconf->sets.entries + envconf->sets.size++;
SetValue:
    *value_slot = vhttp_strdup_shared(NULL, value, SIZE_MAX);
}

void vhttp_config_unsetenv(vhttp_envconf_t *envconf, const char *name)
{
    size_t i, name_len = strlen(name);

    /* do nothing if already set */
    for (i = 0; i != envconf->unsets.size; ++i)
        if (vhttp_memis(envconf->unsets.entries[i].base, envconf->unsets.entries[i].len, name, name_len))
            return;
    /* register */
    vhttp_vector_reserve(NULL, &envconf->unsets, envconf->unsets.size + 1);
    envconf->unsets.entries[envconf->unsets.size++] = vhttp_strdup_shared(NULL, name, name_len);
}

void vhttp_config_init_pathconf(vhttp_pathconf_t *pathconf, vhttp_globalconf_t *globalconf, const char *path, vhttp_mimemap_t *mimemap)
{
    memset(pathconf, 0, sizeof(*pathconf));
    pathconf->global = globalconf;
    if (path != NULL)
        pathconf->path = vhttp_strdup(NULL, path, SIZE_MAX);
    vhttp_mem_addref_shared(mimemap);
    pathconf->mimemap = mimemap;
    pathconf->error_log.emit_request_errors = 1;
}

void vhttp_config_dispose_pathconf(vhttp_pathconf_t *pathconf)
{
#define DESTROY_LIST(type, list)                                                                                                   \
    do {                                                                                                                           \
        size_t i;                                                                                                                  \
        for (i = 0; i != list.size; ++i) {                                                                                         \
            type *e = list.entries[i];                                                                                             \
            if (e->dispose != NULL)                                                                                                \
                e->dispose(e);                                                                                                     \
            free(e);                                                                                                               \
        }                                                                                                                          \
        free(list.entries);                                                                                                        \
    } while (0)
    DESTROY_LIST(vhttp_handler_t, pathconf->handlers);
    DESTROY_LIST(vhttp_filter_t, pathconf->_filters);
    DESTROY_LIST(vhttp_logger_t, pathconf->_loggers);
#undef DESTROY_LIST

    free(pathconf->path.base);
    if (pathconf->mimemap != NULL)
        vhttp_mem_release_shared(pathconf->mimemap);
    if (pathconf->env != NULL)
        vhttp_mem_release_shared(pathconf->env);
}

void vhttp_config_init(vhttp_globalconf_t *config)
{
    memset(config, 0, sizeof(*config));
    config->hosts = vhttp_mem_alloc(sizeof(config->hosts[0]));
    config->hosts[0] = NULL;
    vhttp_linklist_init_anchor(&config->configurators);
    config->server_name = vhttp_iovec_init(vhttp_STRLIT("vhttp/" vhttp_VERSION));
    config->max_request_entity_size = vhttp_DEFAULT_MAX_REQUEST_ENTITY_SIZE;
    config->max_delegations = vhttp_DEFAULT_MAX_DELEGATIONS;
    config->max_reprocesses = vhttp_DEFAULT_MAX_REPROCESSES;
    config->handshake_timeout = vhttp_DEFAULT_HANDSHAKE_TIMEOUT;
    config->http1.req_timeout = vhttp_DEFAULT_HTTP1_REQ_TIMEOUT;
    config->http1.req_io_timeout = vhttp_DEFAULT_HTTP1_REQ_IO_TIMEOUT;
    config->http1.upgrade_to_http2 = vhttp_DEFAULT_HTTP1_UPGRADE_TO_HTTP2;
    config->http2.idle_timeout = vhttp_DEFAULT_HTTP2_IDLE_TIMEOUT;
    config->http2.graceful_shutdown_timeout = vhttp_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT;
    config->proxy.io_timeout = vhttp_DEFAULT_PROXY_IO_TIMEOUT;
    config->proxy.connect_timeout = vhttp_DEFAULT_PROXY_IO_TIMEOUT;
    config->proxy.first_byte_timeout = vhttp_DEFAULT_PROXY_IO_TIMEOUT;
    config->proxy.emit_x_forwarded_headers = 1;
    config->proxy.emit_via_header = 1;
    config->proxy.emit_missing_date_header = 1;
    config->proxy.zerocopy = vhttp_PROXY_ZEROCOPY_ENABLED;
    config->http2.max_streams = vhttp_HTTP2_SETTINGS_HOST_MAX_CONCURRENT_STREAMS;
    config->http2.max_concurrent_requests_per_connection = vhttp_HTTP2_SETTINGS_HOST_MAX_CONCURRENT_STREAMS;
    config->http2.max_concurrent_streaming_requests_per_connection = vhttp_HTTP2_DEFAULT_MAX_CONCURRENT_STREAMING_REQUESTS;
    config->http2.max_streams_for_priority = 16;
    config->http2.active_stream_window_size = vhttp_DEFAULT_HTTP2_ACTIVE_STREAM_WINDOW_SIZE;
    config->http2.latency_optimization.min_rtt = 50; // milliseconds
    config->http2.latency_optimization.max_additional_delay = 10;
    config->http2.latency_optimization.max_cwnd = 65535;
    config->http2.dos_delay = 100; /* 100ms processing delay when observing suspicious behavior */
    config->http3.idle_timeout = quicly_spec_context.transport_params.max_idle_timeout;
    config->http3.active_stream_window_size = vhttp_DEFAULT_HTTP3_ACTIVE_STREAM_WINDOW_SIZE;
    config->http3.allow_delayed_ack = 1;
    config->http3.use_gso = 1;
    config->http3.max_concurrent_streaming_requests_per_connection = vhttp_HTTP3_DEFAULT_MAX_CONCURRENT_STREAMING_REQUESTS;
    config->send_informational_mode = vhttp_SEND_INFORMATIONAL_MODE_EXCEPT_H1;
    config->mimemap = vhttp_mimemap_create();
    vhttp_socketpool_init_global(&config->proxy.global_socketpool, SIZE_MAX);

    vhttp_configurator__init_core(config);

    config->fallback_host = create_hostconf(config);
    config->fallback_host->authority.port = 65535;
    config->fallback_host->authority.host = vhttp_strdup(NULL, vhttp_STRLIT("*"));
    config->fallback_host->authority.hostport = vhttp_strdup(NULL, vhttp_STRLIT("*"));
}

vhttp_pathconf_t *vhttp_config_register_path(vhttp_hostconf_t *hostconf, const char *path, int flags)
{
    vhttp_pathconf_t *pathconf = vhttp_mem_alloc(sizeof(*pathconf));
    vhttp_config_init_pathconf(pathconf, hostconf->global, path, hostconf->mimemap);

    /* Find the slot to insert the new pathconf. Sort order is descending by the path length so that longer pathconfs overriding
     * subdirectories of shorter ones would work, regardless of the regisration order. Pathconfs sharing the same length are sorted
     * in the ascending order of memcmp / strcmp (as we have always done in the vhttp standalone server). */
    size_t slot;
    for (slot = 0; slot < hostconf->paths.size; ++slot) {
        if (pathconf->path.len > hostconf->paths.entries[slot]->path.len)
            break;
        if (pathconf->path.len == hostconf->paths.entries[slot]->path.len &&
            memcmp(pathconf->path.base, hostconf->paths.entries[slot]->path.base, pathconf->path.len) < 0)
            break;
    }

    vhttp_vector_reserve(NULL, &hostconf->paths, hostconf->paths.size + 1);
    if (slot < hostconf->paths.size)
        memmove(hostconf->paths.entries + slot + 1, hostconf->paths.entries + slot,
                (hostconf->paths.size - slot) * sizeof(hostconf->paths.entries[0]));
    hostconf->paths.entries[slot] = pathconf;
    ++hostconf->paths.size;

    return pathconf;
}

void vhttp_config_register_status_handler(vhttp_globalconf_t *config, vhttp_status_handler_t *status_handler)
{
    /* check if the status handler is already registered */
    size_t i;
    for (i = 0; i != config->statuses.size; ++i)
        if (config->statuses.entries[i] == status_handler)
            return;
    /* register the new handler */
    vhttp_vector_reserve(NULL, &config->statuses, config->statuses.size + 1);
    config->statuses.entries[config->statuses.size++] = status_handler;
}

vhttp_hostconf_t *vhttp_config_register_host(vhttp_globalconf_t *config, vhttp_iovec_t host, uint16_t port)
{
    vhttp_hostconf_t *hostconf = NULL;
    vhttp_iovec_t host_lc;

    assert(host.len != 0);

    /* convert hostname to lowercase */
    host_lc = vhttp_strdup(NULL, host.base, host.len);
    vhttp_strtolower(host_lc.base, host_lc.len);

    { /* return NULL if given authority is already registered */
        vhttp_hostconf_t **p;
        for (p = config->hosts; *p != NULL; ++p)
            if (vhttp_memis((*p)->authority.host.base, (*p)->authority.host.len, host_lc.base, host_lc.len) &&
                (*p)->authority.port == port)
                goto Exit;
    }

    /* create hostconf */
    hostconf = create_hostconf(config);
    hostconf->authority.host = host_lc;
    host_lc = (vhttp_iovec_t){NULL};
    hostconf->authority.port = port;
    if (hostconf->authority.port == 65535) {
        hostconf->authority.hostport = hostconf->authority.host;
    } else {
        hostconf->authority.hostport.base = vhttp_mem_alloc(hostconf->authority.host.len + sizeof("[]:" vhttp_UINT16_LONGEST_STR));
        if (strchr(hostconf->authority.host.base, ':') != NULL) {
            hostconf->authority.hostport.len =
                sprintf(hostconf->authority.hostport.base, "[%s]:%" PRIu16, hostconf->authority.host.base, port);
        } else {
            hostconf->authority.hostport.len =
                sprintf(hostconf->authority.hostport.base, "%s:%" PRIu16, hostconf->authority.host.base, port);
        }
    }

    /* append to the list */
    vhttp_append_to_null_terminated_list((void *)&config->hosts, hostconf);

Exit:
    free(host_lc.base);
    return hostconf;
}

void vhttp_config_dispose(vhttp_globalconf_t *config)
{
    size_t i;

    for (i = 0; config->hosts[i] != NULL; ++i) {
        vhttp_hostconf_t *hostconf = config->hosts[i];
        destroy_hostconf(hostconf);
    }
    free(config->hosts);

    destroy_hostconf(config->fallback_host);

    vhttp_socketpool_dispose(&config->proxy.global_socketpool);
    vhttp_mem_release_shared(config->mimemap);
    vhttp_configurator__dispose_configurators(config);
}

vhttp_handler_t *vhttp_create_handler(vhttp_pathconf_t *conf, size_t sz)
{
    vhttp_handler_t *handler = vhttp_mem_alloc(sz);

    memset(handler, 0, sz);
    handler->_config_slot = conf->global->_num_config_slots++;

    vhttp_vector_reserve(NULL, &conf->handlers, conf->handlers.size + 1);
    conf->handlers.entries[conf->handlers.size++] = handler;

    return handler;
}

vhttp_filter_t *vhttp_create_filter(vhttp_pathconf_t *conf, size_t sz)
{
    vhttp_filter_t *filter = vhttp_mem_alloc(sz);

    memset(filter, 0, sz);
    filter->_config_slot = conf->global->_num_config_slots++;

    vhttp_vector_reserve(NULL, &conf->_filters, conf->_filters.size + 1);
    memmove(conf->_filters.entries + 1, conf->_filters.entries, conf->_filters.size * sizeof(conf->_filters.entries[0]));
    conf->_filters.entries[0] = filter;
    ++conf->_filters.size;

    return filter;
}

vhttp_logger_t *vhttp_create_logger(vhttp_pathconf_t *conf, size_t sz)
{
    vhttp_logger_t *logger = vhttp_mem_alloc(sz);

    memset(logger, 0, sz);
    logger->_config_slot = conf->global->_num_config_slots++;

    vhttp_vector_reserve(NULL, &conf->_loggers, conf->_loggers.size + 1);
    conf->_loggers.entries[conf->_loggers.size++] = logger;

    return logger;
}
