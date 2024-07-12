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
#ifndef vhttp_h
#define vhttp_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include "vhttp/filecache.h"
#include "vhttp/header.h"
#include "vhttp/hostinfo.h"
#include "vhttp/memcached.h"
#include "vhttp/redis.h"
#include "vhttp/linklist.h"
#include "vhttp/httpclient.h"
#include "vhttp/memory.h"
#include "vhttp/multithread.h"
#include "vhttp/rand.h"
#include "vhttp/socket.h"
#include "vhttp/string_.h"
#include "vhttp/time_.h"
#include "vhttp/token.h"
#include "vhttp/url.h"
#include "vhttp/balancer.h"
#include "vhttp/http2_common.h"
#include "vhttp/send_state.h"

#ifndef vhttp_USE_BROTLI
/* disabled for all but the standalone server, since the encoder is written in C++ */
#define vhttp_USE_BROTLI 0
#endif

#ifndef vhttp_MAX_HEADERS
#define vhttp_MAX_HEADERS 100
#endif
#ifndef vhttp_MAX_REQLEN
#define vhttp_MAX_REQLEN (8192 + 4096 * (vhttp_MAX_HEADERS))
#endif

#ifndef vhttp_SOMAXCONN
/* simply use a large value, and let the kernel clip it to the internal max */
#define vhttp_SOMAXCONN 65535
#endif

#define vhttp_HTTP2_MIN_STREAM_WINDOW_SIZE 65535
#define vhttp_HTTP2_MAX_STREAM_WINDOW_SIZE 16777216

#define vhttp_DEFAULT_MAX_REQUEST_ENTITY_SIZE (1024 * 1024 * 1024)
#define vhttp_DEFAULT_MAX_DELEGATIONS 5
#define vhttp_DEFAULT_MAX_REPROCESSES 5
#define vhttp_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS 10
#define vhttp_DEFAULT_HANDSHAKE_TIMEOUT (vhttp_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS * 1000)
#define vhttp_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS 10
#define vhttp_DEFAULT_HTTP1_REQ_TIMEOUT (vhttp_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS * 1000)
#define vhttp_DEFAULT_HTTP1_REQ_IO_TIMEOUT_IN_SECS 5
#define vhttp_DEFAULT_HTTP1_REQ_IO_TIMEOUT (vhttp_DEFAULT_HTTP1_REQ_IO_TIMEOUT_IN_SECS * 1000)
#define vhttp_DEFAULT_HTTP1_UPGRADE_TO_HTTP2 1
#define vhttp_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS 10
#define vhttp_DEFAULT_HTTP2_IDLE_TIMEOUT (vhttp_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS * 1000)
#define vhttp_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT_IN_SECS 0 /* no timeout */
#define vhttp_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT (vhttp_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT_IN_SECS * 1000)
#define vhttp_DEFAULT_HTTP2_ACTIVE_STREAM_WINDOW_SIZE vhttp_HTTP2_MAX_STREAM_WINDOW_SIZE
#define vhttp_DEFAULT_HTTP3_ACTIVE_STREAM_WINDOW_SIZE vhttp_DEFAULT_HTTP2_ACTIVE_STREAM_WINDOW_SIZE
#define vhttp_DEFAULT_PROXY_IO_TIMEOUT_IN_SECS 30
#define vhttp_DEFAULT_PROXY_IO_TIMEOUT (vhttp_DEFAULT_PROXY_IO_TIMEOUT_IN_SECS * 1000)
#define vhttp_DEFAULT_HAPPY_EYEBALLS_NAME_RESOLUTION_DELAY 50
#define vhttp_DEFAULT_HAPPY_EYEBALLS_CONNECTION_ATTEMPT_DELAY 250
#define vhttp_DEFAULT_PROXY_SSL_SESSION_CACHE_CAPACITY 4096
#define vhttp_DEFAULT_PROXY_SSL_SESSION_CACHE_DURATION 86400000 /* 24 hours */
#define vhttp_DEFAULT_PROXY_HTTP2_MAX_CONCURRENT_STREAMS 100

#define vhttp_LOG_URI_PATH "/.well-known/vhttplog"

typedef struct st_vhttp_conn_t vhttp_conn_t;
typedef struct st_vhttp_context_t vhttp_context_t;
typedef struct st_vhttp_req_t vhttp_req_t;
typedef struct st_vhttp_ostream_t vhttp_ostream_t;
typedef struct st_vhttp_configurator_command_t vhttp_configurator_command_t;
typedef struct st_vhttp_configurator_t vhttp_configurator_t;
typedef struct st_vhttp_pathconf_t vhttp_pathconf_t;
typedef struct st_vhttp_hostconf_t vhttp_hostconf_t;
typedef struct st_vhttp_globalconf_t vhttp_globalconf_t;
typedef struct st_vhttp_mimemap_t vhttp_mimemap_t;
typedef struct st_vhttp_logconf_t vhttp_logconf_t;
typedef struct st_vhttp_headers_command_t vhttp_headers_command_t;

/**
 * basic structure of a handler (an object that MAY generate a response)
 * The handlers should register themselves to vhttp_context_t::handlers.
 */
typedef struct st_vhttp_handler_t {
    size_t _config_slot;
    void (*on_context_init)(struct st_vhttp_handler_t *self, vhttp_context_t *ctx);
    void (*on_context_dispose)(struct st_vhttp_handler_t *self, vhttp_context_t *ctx);
    void (*dispose)(struct st_vhttp_handler_t *self);
    int (*on_req)(struct st_vhttp_handler_t *self, vhttp_req_t *req);
    /**
     * If the flag is set, protocol handler may invoke the request handler before receiving the end of the request body. The request
     * handler can determine if the protocol handler has actually done so by checking if `req->proceed_req` is set to non-NULL.
     * In such case, the handler should replace `req->write_req.cb` (and ctx) with its own callback to receive the request body
     * bypassing the buffer of the protocol handler. Parts of the request body being received before the handler replacing the
     * callback is accessible via `req->entity`.
     * The request handler can delay replacing the callback to a later moment. In such case, the handler can determine if
     * `req->entity` already contains a complete request body by checking if `req->proceed_req` is NULL.
     */
    unsigned supports_request_streaming : 1;
} vhttp_handler_t;

/**
 * basic structure of a filter (an object that MAY modify a response)
 * The filters should register themselves to vhttp_context_t::filters.
 */
typedef struct st_vhttp_filter_t {
    size_t _config_slot;
    void (*on_context_init)(struct st_vhttp_filter_t *self, vhttp_context_t *ctx);
    void (*on_context_dispose)(struct st_vhttp_filter_t *self, vhttp_context_t *ctx);
    void (*dispose)(struct st_vhttp_filter_t *self);
    void (*on_setup_ostream)(struct st_vhttp_filter_t *self, vhttp_req_t *req, vhttp_ostream_t **slot);
    void (*on_informational)(struct st_vhttp_filter_t *self, vhttp_req_t *req);
} vhttp_filter_t;

/**
 * basic structure of a logger (an object that MAY log a request)
 * The loggers should register themselves to vhttp_context_t::loggers.
 */
typedef struct st_vhttp_logger_t {
    size_t _config_slot;
    void (*on_context_init)(struct st_vhttp_logger_t *self, vhttp_context_t *ctx);
    void (*on_context_dispose)(struct st_vhttp_logger_t *self, vhttp_context_t *ctx);
    void (*dispose)(struct st_vhttp_logger_t *self);
    void (*log_access)(struct st_vhttp_logger_t *self, vhttp_req_t *req);
} vhttp_logger_t;

/**
 * contains stringified representations of a timestamp
 */
typedef struct st_vhttp_timestamp_string_t {
    char rfc1123[vhttp_TIMESTR_RFC1123_LEN + 1];
    char log[vhttp_TIMESTR_LOG_LEN + 1];
} vhttp_timestamp_string_t;

/**
 * a timestamp.
 * Applications should call vhttp_get_timestamp to obtain a timestamp.
 */
typedef struct st_vhttp_timestamp_t {
    struct timeval at;
    vhttp_timestamp_string_t *str;
} vhttp_timestamp_t;

typedef struct st_vhttp_casper_conf_t {
    /**
     * capacity bits (0 to disable casper)
     */
    unsigned capacity_bits;
    /**
     * whether if all type of files should be tracked (or only the blocking assets)
     */
    int track_all_types;
} vhttp_casper_conf_t;

typedef struct st_vhttp_envconf_t {
    /**
     * parent
     */
    struct st_vhttp_envconf_t *parent;
    /**
     * list of names to be unset
     */
    vhttp_iovec_vector_t unsets;
    /**
     * list of name-value pairs to be set
     */
    vhttp_iovec_vector_t sets;
} vhttp_envconf_t;

struct st_vhttp_pathconf_t {
    /**
     * globalconf to which the pathconf belongs
     */
    vhttp_globalconf_t *global;
    /**
     * pathname in lower case, may or may not have "/" at last, NULL terminated, or is {NULL,0} if is fallback or extension-level
     */
    vhttp_iovec_t path;
    /**
     * list of handlers
     */
    vhttp_VECTOR(vhttp_handler_t *) handlers;
    /**
     * list of filters to be applied unless when processing a subrequest.
     * The address of the list is set in `req->filters` and used when processing a request.
     */
    vhttp_VECTOR(vhttp_filter_t *) _filters;
    /**
     * list of loggers to be applied unless when processing a subrequest.
     * The address of the list is set in `req->loggers` and used when processing a request.
     */
    vhttp_VECTOR(vhttp_logger_t *) _loggers;
    /**
     * mimemap
     */
    vhttp_mimemap_t *mimemap;
    /**
     * env
     */
    vhttp_envconf_t *env;
    /**
     * error-log
     */
    struct {
        /**
         * if request-level errors should be emitted to stderr
         */
        unsigned emit_request_errors : 1;
    } error_log;
};

struct st_vhttp_hostconf_t {
    /**
     * reverse reference to the global configuration
     */
    vhttp_globalconf_t *global;
    /**
     * host and port
     */
    struct {
        /**
         * host and port (in lower-case; base is NULL-terminated)
         */
        vhttp_iovec_t hostport;
        /**
         *  in lower-case; base is NULL-terminated
         */
        vhttp_iovec_t host;
        /**
         * port number (or 65535 if default)
         */
        uint16_t port;
    } authority;
    /**
     * A boolean indicating that this hostconf can only be used for a request with the ":authority" pseudo-header field / "Host"
     * that matches hostport. When strict_match is false, then this hostconf is eligible for use as the fallback hostconf for a
     * request that does not match any applicable hostconf.
     */
    uint8_t strict_match;
    /**
     * list of path configurations
     */
    vhttp_VECTOR(vhttp_pathconf_t *) paths;
    /**
     * catch-all path configuration
     */
    vhttp_pathconf_t fallback_path;
    /**
     * mimemap
     */
    vhttp_mimemap_t *mimemap;
    /**
     * http2
     */
    struct {
        /**
         * whether if blocking assets being pulled should be given highest priority in case of clients that do not implement
         * dependency-based prioritization
         */
        unsigned reprioritize_blocking_assets : 1;
        /**
         * if server push should be used
         */
        unsigned push_preload : 1;
        /**
         * if cross origin pushes should be authorized
         */
        unsigned allow_cross_origin_push : 1;
        /**
         * casper settings
         */
        vhttp_casper_conf_t casper;
    } http2;
};

typedef vhttp_iovec_t (*final_status_handler_cb)(void *ctx, vhttp_globalconf_t *gconf, vhttp_req_t *req);
typedef const struct st_vhttp_status_handler_t {
    vhttp_iovec_t name;
    vhttp_iovec_t (*final)(void *ctx, vhttp_globalconf_t *gconf, vhttp_req_t *req); /* mandatory, will be passed the optional context */
    void *(*init)(void); /* optional callback, allocates a context that will be passed to per_thread() */
    void (*per_thread)(void *priv, vhttp_context_t *ctx); /* optional callback, will be called for each thread */
} vhttp_status_handler_t;

typedef vhttp_VECTOR(vhttp_status_handler_t *) vhttp_status_callbacks_t;

typedef enum vhttp_send_informational_mode {
    vhttp_SEND_INFORMATIONAL_MODE_EXCEPT_H1,
    vhttp_SEND_INFORMATIONAL_MODE_NONE,
    vhttp_SEND_INFORMATIONAL_MODE_ALL
} vhttp_send_informational_mode_t;

/**
 * If zero copy should be used. "Always" indicates to the proxy handler that pipe-backed vectors should be used even when the http
 * protocol handler does not support zerocopy. This mode delays the load of content to userspace, at the cost of moving around
 * memory page between the socket connected to the origin and the pipe.
 */
typedef enum vhttp_proxy_zerocopy_mode {
    vhttp_PROXY_ZEROCOPY_DISABLED,
    vhttp_PROXY_ZEROCOPY_ENABLED,
    vhttp_PROXY_ZEROCOPY_ALWAYS
} vhttp_proxy_zerocopy_mode_t;

struct st_vhttp_globalconf_t {
    /**
     * a NULL-terminated list of host contexts (vhttp_hostconf_t)
     */
    vhttp_hostconf_t **hosts;
    /**
     * The hostconf that will be used when none of the hostconfs for the listener match the request and they all have strict-match:
     * ON.
     */
    vhttp_hostconf_t *fallback_host;
    /**
     * list of configurators
     */
    vhttp_linklist_t configurators;
    /**
     * name of the server (not the hostname)
     */
    vhttp_iovec_t server_name;
    /**
     * formated "sf-token" or "sf-string" for the proxy-status header
     */
    vhttp_iovec_t proxy_status_identity;
    /**
     * maximum size of the accepted request entity (e.g. POST data)
     */
    size_t max_request_entity_size;
    /**
     * maximum count for delegations
     */
    unsigned max_delegations;
    /**
     * maximum count for reprocesses
     */
    unsigned max_reprocesses;
    /**
     * setuid user (or NULL)
     */
    char *user;
    /**
     * sets up the vhttp_return map if true.
     */
    int usdt_selective_tracing;

    /**
     * SSL handshake timeout
     */
    uint64_t handshake_timeout;

    struct {
        /**
         * request timeout (in milliseconds)
         */
        uint64_t req_timeout;
        /**
         * request io timeout (in milliseconds)
         */
        uint64_t req_io_timeout;
        /**
         * a boolean value indicating whether or not to upgrade to HTTP/2
         */
        int upgrade_to_http2;
    } http1;

    struct {
        /**
         * idle timeout (in milliseconds)
         */
        uint64_t idle_timeout;
        /**
         * graceful shutdown timeout (in milliseconds)
         */
        uint64_t graceful_shutdown_timeout;
        /**
         * maximum number of HTTP2 streams to accept and advertise via HTTP2 SETTINGS.
         *
         * See max_concurrent_requests_per_connection and max_concurrent_streaming_requests_per_connection below for more info on
         * the actual number of requests that vhttp is willing to process concurrently.
         */
        uint32_t max_streams;
        /**
         * maximum number of HTTP2 requests (per connection) to be handled simultaneously internally.
         * vhttp accepts at most `max_streams` requests over HTTP/2, but internally limits the number of in-flight requests to the
         * value specified by this property in order to limit the resources allocated to a single connection.
         */
        size_t max_concurrent_requests_per_connection;
        /**
         * maximum number of HTTP2 streaming requests (per connection) to be handled simultaneously internally.
         */
        size_t max_concurrent_streaming_requests_per_connection;
        /**
         * maximum nuber of streams (per connection) to be allowed in IDLE / CLOSED state (used for tracking dependencies).
         */
        size_t max_streams_for_priority;
        /**
         * size of the stream-level flow control window (once it becomes active)
         */
        uint32_t active_stream_window_size;
        /**
         * conditions for latency optimization
         */
        vhttp_socket_latency_optimization_conditions_t latency_optimization;
        /* */
        vhttp_iovec_t origin_frame;
        /**
         * milliseconds to delay processing requests when suspicious behavior is detected
         */
        uint64_t dos_delay;
    } http2;

    struct {
        /**
         * idle timeout (in milliseconds)
         */
        uint64_t idle_timeout;
        /**
         * graceful shutdown timeout (in milliseconds)
         */
        uint64_t graceful_shutdown_timeout;
        /**
         * receive window size of the unblocked request stream
         */
        uint32_t active_stream_window_size;
        /**
         * See quicly_context_t::ack_frequency
         */
        uint16_t ack_frequency;
        /**
         * a boolean indicating if the delayed ack extension should be used (default true)
         */
        uint8_t allow_delayed_ack : 1;
        /**
         * a boolean indicating if UDP GSO should be used when possible
         */
        uint8_t use_gso : 1;
        /**
         * maximum number of HTTP3 streaming requests (per connection) to be handled simultaneously internally.
         */
        size_t max_concurrent_streaming_requests_per_connection;
    } http3;

    struct {
        /**
         * io timeout (in milliseconds)
         */
        uint64_t io_timeout;
        /**
         * io timeout (in milliseconds)
         */
        uint64_t connect_timeout;
        /**
         * io timeout (in milliseconds)
         */
        uint64_t first_byte_timeout;
        /**
         * keepalive timeout (in milliseconds)
         */
        uint64_t keepalive_timeout;
        /**
         * a boolean flag if set to true, instructs the proxy to preserve the x-forwarded-proto header passed by the client
         */
        unsigned preserve_x_forwarded_proto : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to preserve the server header passed by the origin
         */
        unsigned preserve_server_header : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to emit x-forwarded-proto and x-forwarded-for headers
         */
        unsigned emit_x_forwarded_headers : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to emit a via header
         */
        unsigned emit_via_header : 1;
        /**
         * a boolean flag if set to true, instructs the proxy to emit a date header, if it's missing from the upstream response
         */
        unsigned emit_missing_date_header : 1;
        /**
         * maximum size to buffer for the response
         */
        size_t max_buffer_size;
        /**
         * maximum number of pipes to retain for reuse
         */
        size_t max_spare_pipes;
        /**
         * a boolean flag if set to true, instructs to use zero copy (i.e., splice to pipe then splice to socket) if possible
         */
        vhttp_proxy_zerocopy_mode_t zerocopy;

        struct {
            uint32_t max_concurrent_streams;
        } http2;

        /**
         * See the documentation of `vhttp_httpclient_t::protocol_selector.ratio`.
         */
        struct {
            int8_t http2;
            int8_t http3;
        } protocol_ratio;

        /**
         * global socketpool
         */
        vhttp_socketpool_t global_socketpool;
    } proxy;

    /**
     * enum indicating to what clients vhttp sends 1xx response
     */
    vhttp_send_informational_mode_t send_informational_mode;

    /**
     * mimemap
     */
    vhttp_mimemap_t *mimemap;

    /**
     * filecache
     */
    struct {
        /* capacity of the filecache */
        size_t capacity;
    } filecache;

    /* status */
    vhttp_status_callbacks_t statuses;

    size_t _num_config_slots;
};

enum {
    vhttp_COMPRESS_HINT_AUTO = 0,    /* default: let vhttp negociate compression based on the configuration */
    vhttp_COMPRESS_HINT_DISABLE,     /* compression was explicitly disabled for this request */
    vhttp_COMPRESS_HINT_ENABLE,      /* compression was explicitly enabled for this request */
    vhttp_COMPRESS_HINT_ENABLE_GZIP, /* compression was explicitly enabled for this request, asking for gzip */
    vhttp_COMPRESS_HINT_ENABLE_BR,   /* compression was explicitly enabled for this request, asking for br */
    vhttp_COMPRESS_HINT_ENABLE_ZSTD, /* compression was explicitly enabled for this request, asking for zstd */
};

/**
 * holds various attributes related to the mime-type
 */
typedef struct st_vhttp_mime_attributes_t {
    /**
     * whether if the content can be compressed by using gzip
     */
    char is_compressible;
    /**
     * how the resource should be prioritized
     */
    enum { vhttp_MIME_ATTRIBUTE_PRIORITY_NORMAL = 0, vhttp_MIME_ATTRIBUTE_PRIORITY_HIGHEST } priority;
} vhttp_mime_attributes_t;

extern vhttp_mime_attributes_t vhttp_mime_attributes_as_is;

/**
 * represents either a mime-type (and associated info), or contains pathinfo in case of a dynamic type (e.g. .php files)
 */
typedef struct st_vhttp_mimemap_type_t {
    enum { vhttp_MIMEMAP_TYPE_MIMETYPE = 0, vhttp_MIMEMAP_TYPE_DYNAMIC = 1 } type;
    union {
        struct {
            vhttp_iovec_t mimetype;
            vhttp_mime_attributes_t attr;
        };
        struct {
            vhttp_pathconf_t pathconf;
        } dynamic;
    } data;
} vhttp_mimemap_type_t;

enum {
    /* http1 protocol errors */
    vhttp_STATUS_ERROR_400 = 0,
    vhttp_STATUS_ERROR_401,
    vhttp_STATUS_ERROR_403,
    vhttp_STATUS_ERROR_404,
    vhttp_STATUS_ERROR_405,
    vhttp_STATUS_ERROR_413,
    vhttp_STATUS_ERROR_416,
    vhttp_STATUS_ERROR_417,
    vhttp_STATUS_ERROR_421,
    vhttp_STATUS_ERROR_500,
    vhttp_STATUS_ERROR_502,
    vhttp_STATUS_ERROR_503,
    vhttp_STATUS_ERROR_MAX,
};

/**
 * holds various data related to the context
 */
typedef struct st_vhttp_context_storage_item_t {
    void (*dispose)(void *data);
    void *data;
} vhttp_context_storage_item_t;

typedef vhttp_VECTOR(vhttp_context_storage_item_t) vhttp_context_storage_t;

typedef enum vhttp_conn_state {
    vhttp_CONN_STATE_IDLE,
    vhttp_CONN_STATE_ACTIVE,
    vhttp_CONN_STATE_SHUTDOWN,
} vhttp_conn_state_t;

/**
 * context of the http server.
 */
struct st_vhttp_context_t {
    /**
     * points to the loop (either uv_loop_t or vhttp_evloop_t, depending on the value of vhttp_USE_LIBUV)
     */
    vhttp_loop_t *loop;
    /**
     * pointer to the global configuration
     */
    vhttp_globalconf_t *globalconf;
    /**
     * queue for receiving messages from other contexts
     */
    vhttp_multithread_queue_t *queue;
    /**
     * receivers
     */
    struct {
        vhttp_multithread_receiver_t hostinfo_getaddr;
    } receivers;
    /**
     * open file cache
     */
    vhttp_filecache_t *filecache;
    /**
     * context scope storage for general use
     */
    vhttp_context_storage_t storage;
    /**
     * flag indicating if shutdown has been requested
     */
    int shutdown_requested;
    /**
     * connection states
     */
    struct {
        /**
         * link-list of vhttp_conn_t
         *
         * list of connections in each state
         *
         * idle:
         *  - newly created connections are `idle`
         *  - `idle` connections become `active` as they receive requests
         *  - `active` connections become `idle` when there are no pending requests
         * active:
         *  - connections that contain pending requests
         * shutdown:
         *  - connections that are shutting down
         */
        vhttp_linklist_t idle, active, shutdown;
        /**
         * number of connections in each state
         */
        union {
            /**
             * counters (the order MUST match that of vhttp_connection_state_t; it is accessed by index via the use of counters[])
             */
            struct {
                size_t idle, active, shutdown;
            };
            size_t counters[1];
        } num_conns;
    } _conns;
    struct {

        struct {
            uint64_t request_timeouts;
            uint64_t request_io_timeouts;
        } events;
    } http1;

    struct {
        struct {
            /**
             * counter for http2 errors internally emitted by vhttp
             */
            uint64_t protocol_level_errors[vhttp_HTTP2_ERROR_MAX];
            /**
             * premature close on read
             */
            uint64_t read_closed;
            /**
             * premature close on write
             */
            uint64_t write_closed;
            /**
             * counter for http2 idle timeouts
             */
            uint64_t idle_timeouts;
            /**
             * streaming request counter
             */
            uint64_t streaming_requests;
        } events;
    } http2;

    struct {
        /**
         * thread-local variable shared by multiple instances of `vhttp_quic_ctx_t::next_cid`
         */
        quicly_cid_plaintext_t next_cid;
        /**
         *
         */
        struct {
            /**
             * number of packets forwarded to another node in a cluster
             */
            uint64_t packet_forwarded;
            /**
             * number of forwarded packets received from another node in a cluster
             */
            uint64_t forwarded_packet_received;
        } events;
    } http3;

    struct {
        /**
         * the default client context for proxy
         */
        vhttp_httpclient_ctx_t client_ctx;
        /**
         * the default connection pool for proxy
         */
        vhttp_httpclient_connection_pool_t connpool;
        /**
         * the list of spare pipes currently retained for reuse
         */
        struct {
            int (*pipes)[2];
            size_t count;
        } spare_pipes;
    } proxy;

    struct {
        /**
         * counter for SSL errors
         */
        uint64_t errors;
        /**
         * counter for selected ALPN protocols
         */
        uint64_t alpn_h1;
        uint64_t alpn_h2;
        /**
         * counter for handshakes
         */
        uint64_t handshake_full;
        uint64_t handshake_resume;
        /**
         * summations of handshake latency in microsecond
         */
        uint64_t handshake_accum_time_full;
        uint64_t handshake_accum_time_resume;
    } ssl;

    /**
     * aggregated quic stats
     */
    vhttp_quic_stats_t quic_stats;

    /**
     * connection stats
     */
    struct {
        uint64_t idle_closed;
    } connection_stats;

    /**
     * pointer to per-module configs
     */
    void **_module_configs;

    struct {
        struct timeval tv_at;
        vhttp_timestamp_string_t *value;
    } _timestamp_cache;

    /**
     * counter for http1 error status internally emitted by vhttp
     */
    uint64_t emitted_error_status[vhttp_STATUS_ERROR_MAX];

    vhttp_VECTOR(vhttp_pathconf_t *) _pathconfs_inited;
};

/**
 * an object that generates a response.
 * The object is typically constructed by handlers calling the vhttp_start_response function.
 */
typedef struct st_vhttp_generator_t {
    /**
     * called by the core to request new data to be pushed via the vhttp_send function.
     */
    void (*proceed)(struct st_vhttp_generator_t *self, vhttp_req_t *req);
    /**
     * called by the core when there is a need to terminate the response abruptly
     */
    void (*stop)(struct st_vhttp_generator_t *self, vhttp_req_t *req);
} vhttp_generator_t;

/**
 * an output stream that may alter the output.
 * The object is typically constructed by filters calling the vhttp_prepend_ostream function.
 */
struct st_vhttp_ostream_t {
    /**
     * points to the next output stream
     */
    struct st_vhttp_ostream_t *next;
    /**
     * called by the core to send output.
     * Intermediary output streams should process the given output and call the vhttp_ostream_send_next function if any data can be
     * sent.
     */
    void (*do_send)(struct st_vhttp_ostream_t *self, vhttp_req_t *req, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_send_state_t state);
    /**
     * called by the core when there is a need to terminate the response abruptly
     */
    void (*stop)(struct st_vhttp_ostream_t *self, vhttp_req_t *req);
    /**
     * called by the core via vhttp_send_informational
     */
    void (*send_informational)(struct st_vhttp_ostream_t *self, vhttp_req_t *req);
};

/**
 * a HTTP response
 */
typedef struct st_vhttp_res_t {
    /**
     * status code
     */
    int status;
    /**
     * reason phrase
     */
    const char *reason;
    /**
     * length of the content (that is sent as the Content-Length header).
     * The default value is SIZE_MAX, which means that the length is indeterminate.
     * Generators should set this value whenever possible.
     */
    size_t content_length;
    /**
     * list of response headers
     */
    vhttp_headers_t headers;
    /**
     * list of response trailers
     */
    vhttp_headers_t trailers;
    /**
     * mime-related attributes (may be NULL)
     */
    vhttp_mime_attributes_t *mime_attr;
    /**
     * retains the original response header before rewritten by ostream filters
     */
    struct {
        int status;
        vhttp_headers_t headers;
    } original;
} vhttp_res_t;

/**
 * debug state (currently only for HTTP/2)
 */
typedef struct st_vhttp_http2_debug_state_t {
    vhttp_iovec_vector_t json;
    ssize_t conn_flow_in;
    ssize_t conn_flow_out;
} vhttp_http2_debug_state_t;

typedef struct st_vhttp_conn_callbacks_t {
    /**
     * getsockname (return size of the obtained address, or 0 if failed)
     */
    socklen_t (*get_sockname)(vhttp_conn_t *conn, struct sockaddr *sa);
    /**
     * getpeername (return size of the obtained address, or 0 if failed)
     */
    socklen_t (*get_peername)(vhttp_conn_t *conn, struct sockaddr *sa);
    /**
     * returns picotls connection object used by the connection (or NULL if TLS is not used)
     */
    ptls_t *(*get_ptls)(vhttp_conn_t *conn);
    /**
     * returns if the connection is target of tracing
     */
    int (*skip_tracing)(vhttp_conn_t *conn);
    /**
     * optional (i.e. may be NULL) callback for server push
     */
    void (*push_path)(vhttp_req_t *req, const char *abspath, size_t abspath_len, int is_critical);
    /**
     * debug state callback (optional)
     */
    vhttp_http2_debug_state_t *(*get_debug_state)(vhttp_req_t *req, int hpack_enabled);
    /**
     * returns number of closed idle connections
     */
    void (*close_idle_connection)(vhttp_conn_t *conn);
    /**
     * shutdown of connection is requested
     */
    void (*request_shutdown)(vhttp_conn_t *conn);
    /**
     * for each request
     */
    int (*foreach_request)(vhttp_conn_t *conn, int (*cb)(vhttp_req_t *req, void *cbdata), void *cbdata);
    /**
     * returns number of requests inflight (optional, only supported by H2, H3)
     */
    uint32_t (*num_reqs_inflight)(vhttp_conn_t *conn);
    /**
     * optional callbacks that return the tracer registry
     */
    quicly_tracer_t *(*get_tracer)(vhttp_conn_t *conn);
    /**
     * An optional callback reporting an RTT estimate between the HTTP server and the HTTP client, measured in microseconds. At the
     * moment, this callback is available only for HTTP/2. For HTTP/2, time difference between when the SETTINGS frame was sent and
     * when a SETTINGS-ack was received is used as the estimate. The callback will return a negative value if the information is not
     * yet available.
     */
    int64_t (*get_rtt)(vhttp_conn_t *conn);
    /**
     * optional callback that returns if zero copy is supported by the HTTP handler
     */
    int (*can_zerocopy)(vhttp_conn_t *conn);
    /**
     * Mandatory callback that returns a number identifying the request of a particular connection (e.g., HTTP/2 stream ID)
     */
    uint64_t (*get_req_id)(vhttp_req_t *req);
    /**
     * An optional callback to move the ownership of the socket to the caller. It returns non-null for cleartext connections
     * and thus the caller can call vhttp_socket_export() and write cleartext to its fd.
     */
    vhttp_socket_t *(*steal_socket)(vhttp_conn_t *conn);
    /**
     * logging callbacks (all of them are optional)
     */
    union {
        struct {
            vhttp_iovec_t (*extensible_priorities)(vhttp_req_t *req);
            struct {
                vhttp_iovec_t (*cc_name)(vhttp_req_t *req);
                vhttp_iovec_t (*delivery_rate)(vhttp_req_t *req);
            } transport;
            struct {
                vhttp_iovec_t (*protocol_version)(vhttp_req_t *req);
                vhttp_iovec_t (*session_reused)(vhttp_req_t *req);
                vhttp_iovec_t (*cipher)(vhttp_req_t *req);
                vhttp_iovec_t (*cipher_bits)(vhttp_req_t *req);
                vhttp_iovec_t (*session_id)(vhttp_req_t *req);
                vhttp_iovec_t (*server_name)(vhttp_req_t *req);
                vhttp_iovec_t (*negotiated_protocol)(vhttp_req_t *req);
                vhttp_iovec_t (*ech_config_id)(vhttp_req_t *req);
                vhttp_iovec_t (*ech_kem)(vhttp_req_t *req);
                vhttp_iovec_t (*ech_cipher)(vhttp_req_t *req);
                vhttp_iovec_t (*ech_cipher_bits)(vhttp_req_t *req);
                vhttp_iovec_t (*backend)(vhttp_req_t *req);
            } ssl;
            struct {
                vhttp_iovec_t (*request_index)(vhttp_req_t *req);
            } http1;
            struct {
                vhttp_iovec_t (*stream_id)(vhttp_req_t *req);
                vhttp_iovec_t (*priority_received)(vhttp_req_t *req);
                vhttp_iovec_t (*priority_received_exclusive)(vhttp_req_t *req);
                vhttp_iovec_t (*priority_received_parent)(vhttp_req_t *req);
                vhttp_iovec_t (*priority_received_weight)(vhttp_req_t *req);
                vhttp_iovec_t (*priority_actual)(vhttp_req_t *req);
                vhttp_iovec_t (*priority_actual_parent)(vhttp_req_t *req);
                vhttp_iovec_t (*priority_actual_weight)(vhttp_req_t *req);
            } http2;
            struct {
                vhttp_iovec_t (*stream_id)(vhttp_req_t *req);
                vhttp_iovec_t (*quic_stats)(vhttp_req_t *req);
                vhttp_iovec_t (*quic_version)(vhttp_req_t *req);
            } http3;
        };
        vhttp_iovec_t (*callbacks[1])(vhttp_req_t *req);
    } log_;
} vhttp_conn_callbacks_t;

/**
 * basic structure of an HTTP connection (HTTP/1, HTTP/2, etc.)
 */
struct st_vhttp_conn_t {
    /**
     * the context of the server
     */
    vhttp_context_t *ctx;
    /**
     * NULL-terminated list of hostconfs bound to the connection
     */
    vhttp_hostconf_t **hosts;
    /**
     * time when the connection was established
     */
    struct timeval connected_at;
    /**
     * connection id
     */
    uint64_t id;
    /**
     * callbacks
     */
    const vhttp_conn_callbacks_t *callbacks;
    /**
     * connection UUID (UUIDv4 in the string representation).
     */
    struct {
        char str[vhttp_UUID_STR_RFC4122_LEN + 1];
        uint8_t is_initialized;
    } _uuid;
    vhttp_conn_state_t state;
    /* internal structure */
    vhttp_linklist_t _conns;
};

#define NOPAREN(...) __VA_ARGS__
#define vhttp_CONN_LIST_FOREACH(decl_var, conn_list, block)                                                                          \
    do {                                                                                                                           \
        vhttp_linklist_t *_conn_list[] = NOPAREN conn_list;                                                                          \
        size_t conn_list_len = PTLS_ELEMENTSOF(_conn_list);                                                                        \
        vhttp_linklist_t **_conn_list_iter = (_conn_list);                                                                           \
        for (size_t i = 0; i < conn_list_len; i++) {                                                                               \
            for (vhttp_linklist_t *_node = _conn_list_iter[i]->next, *_node_next; _node != _conn_list_iter[i]; _node = _node_next) { \
                _node_next = _node->next;                                                                                          \
                vhttp_conn_t *_vhttp_conn = vhttp_STRUCT_FROM_MEMBER(vhttp_conn_t, _conns, _node);                                         \
                decl_var = (void *)_vhttp_conn;                                                                                      \
                {                                                                                                                  \
                    block                                                                                                          \
                }                                                                                                                  \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

/**
 * filter used for capturing a response (can be used to implement subreq)
 */
typedef struct st_vhttp_req_prefilter_t {
    struct st_vhttp_req_prefilter_t *next;
    void (*on_setup_ostream)(struct st_vhttp_req_prefilter_t *self, vhttp_req_t *req, vhttp_ostream_t **slot);
} vhttp_req_prefilter_t;

typedef struct st_vhttp_req_overrides_t {
    /**
     * specific client context (or NULL)
     */
    vhttp_httpclient_ctx_t *client_ctx;
    /**
     * connpool to be used when connecting to upstream (or NULL)
     */
    vhttp_httpclient_connection_pool_t *connpool;
    /**
     * upstream to connect to (or NULL)
     */
    vhttp_url_t *upstream;
    /**
     * parameters for rewriting the `Location` header (only used if match.len != 0)
     */
    struct {
        /**
         * if the prefix of the location header matches the url, then the header will be rewritten
         */
        vhttp_url_t *match;
        /**
         * path prefix to be inserted upon rewrite
         */
        vhttp_iovec_t path_prefix;
    } location_rewrite;
    /**
     * whether if the PROXY header should be sent
     */
    unsigned use_proxy_protocol : 1;
    /**
     * whether the proxied request should preserve host
     */
    unsigned proxy_preserve_host : 1;
    /**
     * whether the proxied request sends expect: 100-continue and wait 100 response before sending request body
     */
    unsigned proxy_use_expect : 1;
    /**
     * a boolean flag if set to true, instructs the proxy to close the frontend h1 connection on behalf of the upstream
     */
    unsigned forward_close_connection : 1;
    /**
     * headers rewrite commands to be used when sending requests to upstream (or NULL)
     */
    vhttp_headers_command_t *headers_cmds;
} vhttp_req_overrides_t;

/**
 * additional information for extension-based dynamic content
 */
typedef struct st_vhttp_filereq_t {
    vhttp_iovec_t script_name;
    vhttp_iovec_t path_info;
    vhttp_iovec_t local_path;
} vhttp_filereq_t;

/**
 * Called be the protocol handler to submit chunk of request body to the generator. The callback returns 0 if successful, otherwise
 * a non-zero value. Once `write_req.cb` is called, subsequent invocations MUST be postponed until the `proceed_req` is called. At
 * the moment, `write_req_cb` is required to create a copy of data being provided before returning. To avoid copying, we should
 * consider delegating the responsibility of retaining the buffer to the caller.
 */
typedef int (*vhttp_write_req_cb)(void *ctx, int is_end_stream);
/**
 * Called by the generator, in response to `vhttp_write_req_cb` to indicate to the protocol handler that new chunk can be submitted,
 * or to notify that an error has occurred. In the latter case, write might not be inflight. Note that `errstr` will be NULL (rather
 * than an error code indicating EOS) when called in response to `vhttp_write_req_cb` with `is_end_stream` set to 1.
 */
typedef void (*vhttp_proceed_req_cb)(vhttp_req_t *req, const char *errstr);
/**
 *
 */
typedef void (*vhttp_forward_datagram_cb)(vhttp_req_t *req, vhttp_iovec_t *datagrams, size_t num_datagrams);

#define vhttp_SEND_SERVER_TIMING_BASIC 1
#define vhttp_SEND_SERVER_TIMING_PROXY 2

/**
 * a HTTP request
 */
struct st_vhttp_req_t {
    /**
     * the underlying connection
     */
    vhttp_conn_t *conn;
    /**
     * the request sent by the client (as is)
     */
    struct {
        /**
         * scheme (http, https, etc.)
         */
        const vhttp_url_scheme_t *scheme;
        /**
         * authority (a.k.a. the Host header; the value is supplemented if missing before the handlers are being called)
         */
        vhttp_iovec_t authority;
        /**
         * method
         */
        vhttp_iovec_t method;
        /**
         * abs-path of the request (unmodified)
         */
        vhttp_iovec_t path;
        /**
         * offset of '?' within path, or SIZE_MAX if not found
         */
        size_t query_at;
    } input;
    /**
     * the host context
     */
    vhttp_hostconf_t *hostconf;
    /**
     * the path context
     */
    vhttp_pathconf_t *pathconf;
    /**
     * filters and the size of it
     */
    vhttp_filter_t **filters;
    size_t num_filters;
    /**
     * loggers and the size of it
     */
    vhttp_logger_t **loggers;
    size_t num_loggers;
    /**
     * the handler that has been executed
     */
    vhttp_handler_t *handler;
    /**
     * scheme (http, https, etc.)
     */
    const vhttp_url_scheme_t *scheme;
    /**
     * authority (of the processing request)
     */
    vhttp_iovec_t authority;
    /**
     * method (of the processing request)
     */
    vhttp_iovec_t method;
    /**
     * abs-path of the processing request
     */
    vhttp_iovec_t path;
    /**
     * offset of '?' within path, or SIZE_MAX if not found
     */
    size_t query_at;
    /**
     * normalized path of the processing request (i.e. no "." or "..", no query)
     */
    vhttp_iovec_t path_normalized;
    /**
     * Map of indexes of `path_normalized` into the next character in `path`; built only if `path` required normalization
     */
    size_t *norm_indexes;
    /**
     * authority's prefix matched with `*` against defined hosts
     */
    vhttp_iovec_t authority_wildcard_match;
    /**
     * filters assigned per request
     */
    vhttp_req_prefilter_t *prefilters;
    /**
     * additional information (becomes available for extension-based dynamic content)
     */
    vhttp_filereq_t *filereq;
    /**
     * overrides (maybe NULL)
     */
    vhttp_req_overrides_t *overrides;
    /**
     * the HTTP version (represented as 0xMMmm (M=major, m=minor))
     */
    int version;
    /**
     * list of request headers
     */
    vhttp_headers_t headers;
    /**
     * the request entity (base == NULL if none), can't be used if the handler is streaming the body
     */
    vhttp_iovec_t entity;
    /**
     * amount of request body being received
     */
    size_t req_body_bytes_received;
    /**
     * If different of SIZE_MAX, the numeric value of the received content-length: header
     */
    size_t content_length;
    /**
     * timestamp when the request was processed
     */
    vhttp_timestamp_t processed_at;
    /**
     * additional timestamps
     */
    struct {
        struct timeval request_begin_at;
        struct timeval request_body_begin_at;
        struct timeval response_start_at;
        struct timeval response_end_at;
    } timestamps;
    /**
     * proxy stats
     */
    struct {
        struct {
            uint64_t total;
            uint64_t header;
            uint64_t body;
        } bytes_written;
        struct {
            uint64_t total;
            uint64_t header;
            uint64_t body;
        } bytes_read;
        vhttp_httpclient_timings_t timestamps;
        vhttp_httpclient_conn_properties_t conn;
    } proxy_stats;
    /**
     * the response
     */
    vhttp_res_t res;
    /**
     * number of body bytes sent by the generator (excluding headers)
     */
    uint64_t bytes_sent;
    /**
     * number of header bytes sent by the generator
     */
    uint64_t header_bytes_sent;
    /**
     * the number of times the request can be reprocessed (excluding delegation)
     */
    unsigned remaining_reprocesses;
    /**
     * the number of times the request can be delegated
     */
    unsigned remaining_delegations;

    /**
     * environment variables
     */
    vhttp_iovec_vector_t env;

    /**
     * error log for the request (`vhttp_req_log_error` must be used for error logging)
     */
    vhttp_buffer_t *error_logs;

    /**
     * error log redirection called by `vhttp_req_log_error`. By default, the error is appended to `error_logs`. The callback is
     * replaced by mruby middleware to send the error log to the rack handler.
     */
    struct {
        void (*cb)(void *data, vhttp_iovec_t prefix, vhttp_iovec_t msg);
        void *data;
    } error_log_delegate;

    /* flags */

    /**
     * whether or not the connection is persistent.
     * Applications should set this flag to zero in case the connection cannot be kept keep-alive (due to an error etc.)
     */
    unsigned char http1_is_persistent : 1;
    /**
     * whether if the response has been delegated (i.e. reproxied).
     * For delegated responses, redirect responses would be handled internally.
     */
    unsigned char res_is_delegated : 1;
    /**
     * set by the generator if the protocol handler should replay the request upon seeing 425
     */
    unsigned char reprocess_if_too_early : 1;
    /**
     * set by the proxy handler if the http2 upstream refused the stream so the client can retry the request
     */
    unsigned char upstream_refused : 1;
    /**
     * if vhttp_process_request has been called
     */
    unsigned char process_called : 1;
    /**
     * Indicates if requested to serve something other than HTTP (e.g., websocket, upgrade, CONNECT, ...) using the streaming API.
     * When the protocol handler returns a successful response, filters are skipped.
     */
    unsigned char is_tunnel_req : 1;

    /**
     * whether if the response should include server-timing header. Logical OR of vhttp_SEND_SERVER_TIMING_*
     */
    unsigned send_server_timing;

    /**
     * Whether the producer of the response has explicitly disabled or
     * enabled compression. One of vhttp_COMPRESS_HINT_*
     */
    char compress_hint;

    /**
     * the Upgrade request header (or { NULL, 0 } if not available)
     */
    vhttp_iovec_t upgrade;

    /**
     * preferred chunk size by the ostream
     */
    size_t preferred_chunk_size;

    /**
     * callback and context for receiving request body (see vhttp_handler_t::supports_request_streaming for details)
     */
    struct {
        vhttp_write_req_cb cb;
        void *ctx;
    } write_req;

    /**
     * callback and context for receiving more request body (see vhttp_handler_t::supports_request_streaming for details)
     */
    vhttp_proceed_req_cb proceed_req;

    /**
     * Callbacks for forwarding HTTP/3 Datagrams (RFC 9297).
     * As these callbacks act at the RFC 9297 layer, masque Context IDs (RFC 9298) will be part of the *payload* being exchanged.
     * Write-side is assumed to use `write_req.ctx` for retaining the context if necessary.
     */
    struct {
        vhttp_forward_datagram_cb write_, read_;
    } forward_datagram;

    /* internal structure */
    vhttp_generator_t *_generator;
    vhttp_ostream_t *_ostr_top;
    size_t _next_filter_index;
    vhttp_timer_t _timeout_entry;

    /* per-request memory pool (placed at the last since the structure is large) */
    vhttp_mem_pool_t pool;
};

typedef struct st_vhttp_accept_ctx_t {
    vhttp_context_t *ctx;
    vhttp_hostconf_t **hosts;
    SSL_CTX *ssl_ctx;
    vhttp_iovec_t *http2_origin_frame;
    int expect_proxy_line;
    vhttp_multithread_receiver_t *libmemcached_receiver;
} vhttp_accept_ctx_t;

/* util */

extern const char vhttp_http2_npn_protocols[];
extern const char vhttp_npn_protocols[];
extern const vhttp_iovec_t vhttp_http2_alpn_protocols[];
extern const vhttp_iovec_t vhttp_alpn_protocols[];

/**
 * accepts a connection
 */
void vhttp_accept(vhttp_accept_ctx_t *ctx, vhttp_socket_t *sock);
/**
 * creates a new connection
 */
vhttp_conn_t *vhttp_create_connection(size_t sz, vhttp_context_t *ctx, vhttp_hostconf_t **hosts, struct timeval connected_at,
                                  const vhttp_conn_callbacks_t *callbacks);
/**
 * destroys a connection
 */
void vhttp_destroy_connection(vhttp_conn_t *conn);
/**
 * returns the uuid of the connection as a null-terminated string.
 */
static const char *vhttp_conn_get_uuid(vhttp_conn_t *conn);
/**
 * returns if the connection is still in early-data state (i.e., if there is a risk of received requests being a replay)
 */
static int vhttp_conn_is_early_data(vhttp_conn_t *conn);
/**
 * setups accept context for memcached SSL resumption
 */
void vhttp_accept_setup_memcached_ssl_resumption(vhttp_memcached_context_t *ctx, unsigned expiration);
/**
 * setups accept context for redis SSL resumption
 */
void vhttp_accept_setup_redis_ssl_resumption(const char *host, uint16_t port, unsigned expiration, const char *prefix);
/**
 * returns the protocol version (e.g. "HTTP/1.1", "HTTP/2")
 */
size_t vhttp_stringify_protocol_version(char *dst, int version);
/**
 * builds the proxy header defined by the PROXY PROTOCOL
 */
size_t vhttp_stringify_proxy_header(vhttp_conn_t *conn, char *buf);
#define vhttp_PROXY_HEADER_MAX_LENGTH                                                                                                \
    (sizeof("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n") - 1)
/**
 * extracts path to be pushed from `Link: rel=preload` header.
 */
void vhttp_extract_push_path_from_link_header(vhttp_mem_pool_t *pool, const char *value, size_t value_len, vhttp_iovec_t base_path,
                                            const vhttp_url_scheme_t *input_scheme, vhttp_iovec_t input_authority,
                                            const vhttp_url_scheme_t *base_scheme, vhttp_iovec_t *base_authority,
                                            void (*cb)(void *ctx, const char *path, size_t path_len, int is_critical), void *cb_ctx,
                                            vhttp_iovec_t *filtered_value, int allow_cross_origin_push);
/**
 * return a bitmap of compressible types, by parsing the `accept-encoding` header
 */
int vhttp_get_compressible_types(const vhttp_headers_t *headers);
#define vhttp_COMPRESSIBLE_GZIP 1
#define vhttp_COMPRESSIBLE_BROTLI 2
#define vhttp_COMPRESSIBLE_ZSTD 4
/**
 * builds destination URL or path, by contatenating the prefix and path_info of the request
 */
vhttp_iovec_t vhttp_build_destination(vhttp_req_t *req, const char *prefix, size_t prefix_len, int use_path_normalized);
/**
 * encodes the duration value of the `server-timing` header
 */
void vhttp_add_server_timing_header(vhttp_req_t *req, int uses_trailer);
/**
 * encodes the duration value of the `server-timing` trailer
 */
vhttp_iovec_t vhttp_build_server_timing_trailer(vhttp_req_t *req, const char *prefix, size_t prefix_len, const char *suffix,
                                            size_t suffix_len);
/**
 * Garbage collects resources kept for future reuse in the current thread. If `now` is set to zero, performs full GC. If a valid
 * pointer is passed to `ctx_optional`, resource associated to the context will be collected as well. This function returns how long
 * the next event loop can block before calling `vhttp_cleanup_thread` again, in milliseconds.
 */
uint32_t vhttp_cleanup_thread(uint64_t now, vhttp_context_t *ctx_optional);

extern uint64_t vhttp_connection_id;

/* request */

/**
 * initializes the request structure
 * @param req the request structure
 * @param conn the underlying connection
 * @param src if not NULL, the request structure would be a shallow copy of src
 */
void vhttp_init_request(vhttp_req_t *req, vhttp_conn_t *conn, vhttp_req_t *src);
/**
 * releases resources allocated for handling a request
 */
void vhttp_dispose_request(vhttp_req_t *req);
/**
 * Checks and returns if pseudo headers meet the constraints. This function should be called by each protocol implementation before
 * passing the request to `vhttp_process_request`.
 */
int vhttp_req_validate_pseudo_headers(vhttp_req_t *req);
/**
 * called by the connection layer to start processing a request that is ready
 */
void vhttp_process_request(vhttp_req_t *req);
/**
 * returns the first handler that will be used for the request
 */
vhttp_handler_t *vhttp_get_first_handler(vhttp_req_t *req);
/**
 * delegates the request to the next handler
 */
void vhttp_delegate_request(vhttp_req_t *req);
/**
 * calls vhttp_delegate_request using zero_timeout callback
 */
void vhttp_delegate_request_deferred(vhttp_req_t *req);
/**
 * reprocesses a request once more (used for internal redirection)
 */
void vhttp_reprocess_request(vhttp_req_t *req, vhttp_iovec_t method, const vhttp_url_scheme_t *scheme, vhttp_iovec_t authority,
                           vhttp_iovec_t path, vhttp_req_overrides_t *overrides, int is_delegated);
/**
 * calls vhttp_reprocess_request using zero_timeout callback
 */
void vhttp_reprocess_request_deferred(vhttp_req_t *req, vhttp_iovec_t method, const vhttp_url_scheme_t *scheme, vhttp_iovec_t authority,
                                    vhttp_iovec_t path, vhttp_req_overrides_t *overrides, int is_delegated);
/**
 *
 */
void vhttp_replay_request(vhttp_req_t *req);
/**
 *
 */
void vhttp_replay_request_deferred(vhttp_req_t *req);
/**
 * called by handlers to set the generator
 * @param req the request
 * @param generator the generator
 */
void vhttp_start_response(vhttp_req_t *req, vhttp_generator_t *generator);
/**
 * called by filters to insert output-stream filters for modifying the response
 * @param req the request
 * @param alignment of the memory to be allocated for the ostream filter
 * @param size of the memory to be allocated for the ostream filter
 * @param slot where the stream should be inserted
 * @return pointer to the ostream filter
 */
vhttp_ostream_t *vhttp_add_ostream(vhttp_req_t *req, size_t alignment, size_t sz, vhttp_ostream_t **slot);
/**
 * prepares the request for processing by looking at the method, URI, headers
 */
vhttp_hostconf_t *vhttp_req_setup(vhttp_req_t *req);
/**
 * applies given environment configuration to the request
 */
void vhttp_req_apply_env(vhttp_req_t *req, vhttp_envconf_t *env);
/**
 * binds configurations to the request
 */
void vhttp_req_bind_conf(vhttp_req_t *req, vhttp_hostconf_t *hostconf, vhttp_pathconf_t *pathconf);
/**
 *
 */
static int vhttp_send_state_is_in_progress(vhttp_send_state_t s);
/**
 * called by the generators to send output
 * note: generators should free itself after sending the final chunk (i.e. calling the function with is_final set to true)
 * @param req the request
 * @param bufs an array of buffers
 * @param bufcnt length of the buffers array
 * @param state describes if the output is final, has an error, or is in progress
 */
void vhttp_send(vhttp_req_t *req, vhttp_iovec_t *bufs, size_t bufcnt, vhttp_send_state_t state);
void vhttp_sendvec(vhttp_req_t *req, vhttp_sendvec_t *vecs, size_t veccnt, vhttp_send_state_t state);
/**
 * creates an uninitialized prefilter and returns pointer to it
 */
vhttp_req_prefilter_t *vhttp_add_prefilter(vhttp_req_t *req, size_t alignment, size_t sz);
/**
 * requests the next prefilter or filter (if any) to setup the ostream if necessary
 */
static void vhttp_setup_next_prefilter(vhttp_req_prefilter_t *self, vhttp_req_t *req, vhttp_ostream_t **slot);
/**
 * requests the next filter (if any) to setup the ostream if necessary
 */
static void vhttp_setup_next_ostream(vhttp_req_t *req, vhttp_ostream_t **slot);
/**
 * called by the ostream filters to send output to the next ostream filter
 * note: ostream filters should free itself after sending the final chunk (i.e. calling the function with is_final set to true)
 * note: ostream filters must not set is_final flag to TRUE unless is_final flag of the do_send callback was set as such
 * @param ostr current ostream filter
 * @param req the request
 * @param bufs an array of buffers
 * @param bufcnt length of the buffers array
 * @param state whether the output is in progress, final, or in error
 */
void vhttp_ostream_send_next(vhttp_ostream_t *ostream, vhttp_req_t *req, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_send_state_t state);
/**
 * called by the connection layer to request additional data to the generator
 */
static void vhttp_proceed_response(vhttp_req_t *req);
void vhttp_proceed_response_deferred(vhttp_req_t *req);
/**
 * if NULL, supplements vhttp_req_t::mime_attr
 */
void vhttp_req_fill_mime_attributes(vhttp_req_t *req);
/**
 * returns an environment variable
 */
static vhttp_iovec_t *vhttp_req_getenv(vhttp_req_t *req, const char *name, size_t name_len, int allocate_if_not_found);
/**
 * unsets an environment variable
 */
static void vhttp_req_unsetenv(vhttp_req_t *req, const char *name, size_t name_len);

/* config */

vhttp_envconf_t *vhttp_config_create_envconf(vhttp_envconf_t *src);
void vhttp_config_setenv(vhttp_envconf_t *envconf, const char *name, const char *value);
void vhttp_config_unsetenv(vhttp_envconf_t *envconf, const char *name);

/**
 * initializes pathconf
 * @param path path to serve, or NULL if fallback or extension-level
 * @param mimemap mimemap to use, or NULL if fallback or extension-level
 */
void vhttp_config_init_pathconf(vhttp_pathconf_t *pathconf, vhttp_globalconf_t *globalconf, const char *path, vhttp_mimemap_t *mimemap);
/**
 *
 */
void vhttp_config_dispose_pathconf(vhttp_pathconf_t *pathconf);
/**
 * initializes the global configuration
 */
void vhttp_config_init(vhttp_globalconf_t *config);
/**
 * registers a host context
 */
vhttp_hostconf_t *vhttp_config_register_host(vhttp_globalconf_t *config, vhttp_iovec_t host, uint16_t port);
/**
 * registers a path context
 * @param hostconf host-level configuration that the path-level configuration belongs to
 * @param path path
 * @param flags unused and must be set to zero
 *
 * Handling of the path argument has changed in version 2.0 (of the standard server).
 *
 * Before 2.0, the function implicitely added a trailing `/` to the supplied path (if it did not end with a `/`), and when receiving
 * a HTTP request for a matching path without the trailing `/`, libvhttp sent a 301 response redirecting the client to a URI with a
 * trailing `/`.
 *
 * Since 2.0, the function retains the exact path given as the argument, and the handlers of the pathconf is invoked if one of the
 * following conditions are met:
 *
 * * request path is an exact match to the configuration path
 * * configuration path does not end with a `/`, and the request path begins with the configuration path followed by a `/`
 */
vhttp_pathconf_t *vhttp_config_register_path(vhttp_hostconf_t *hostconf, const char *path, int flags);
/**
 * registers an extra status handler
 */
void vhttp_config_register_status_handler(vhttp_globalconf_t *config, vhttp_status_handler_t *status_handler);
/**
 * disposes of the resources allocated for the global configuration
 */
void vhttp_config_dispose(vhttp_globalconf_t *config);
/**
 * creates a handler associated to a given pathconf
 */
vhttp_handler_t *vhttp_create_handler(vhttp_pathconf_t *conf, size_t sz);
/**
 * creates a filter associated to a given pathconf
 */
vhttp_filter_t *vhttp_create_filter(vhttp_pathconf_t *conf, size_t sz);
/**
 * creates a logger associated to a given pathconf
 */
vhttp_logger_t *vhttp_create_logger(vhttp_pathconf_t *conf, size_t sz);

/* context */

/**
 * initializes the context
 */
void vhttp_context_init(vhttp_context_t *context, vhttp_loop_t *loop, vhttp_globalconf_t *config);
/**
 * disposes of the resources allocated for the context
 */
void vhttp_context_dispose(vhttp_context_t *context);
/**
 * requests shutdown to the connections governed by the context
 */
void vhttp_context_request_shutdown(vhttp_context_t *context);
/**
 *
 */
void vhttp_context_init_pathconf_context(vhttp_context_t *ctx, vhttp_pathconf_t *pathconf);
/**
 *
 */
void vhttp_context_dispose_pathconf_context(vhttp_context_t *ctx, vhttp_pathconf_t *pathconf);

/**
 * returns current timestamp
 * @param ctx the context
 * @param pool memory pool (used when ts != NULL)
 * @param ts buffer to store the timestamp (optional)
 * @return current time in UTC
 */
static vhttp_timestamp_t vhttp_get_timestamp(vhttp_context_t *ctx, vhttp_mem_pool_t *pool);
void vhttp_context_update_timestamp_string_cache(vhttp_context_t *ctx);
/**
 * Closes at most @max_connections_to_close connections that have been inactive for @min_age milliseconds
 */
void vhttp_context_close_idle_connections(vhttp_context_t *ctx, size_t max_connections_to_close, uint64_t min_age);
/**
 * transition connection state
 */
void vhttp_conn_set_state(vhttp_conn_t *conn, vhttp_conn_state_t state);
/**
 * returns per-module context set
 */
static void *vhttp_context_get_handler_context(vhttp_context_t *ctx, vhttp_handler_t *handler);
/**
 * sets per-module context
 */
static void vhttp_context_set_handler_context(vhttp_context_t *ctx, vhttp_handler_t *handler, void *handler_ctx);
/**
 * returns per-module context set by the on_context_init callback
 */
static void *vhttp_context_get_filter_context(vhttp_context_t *ctx, vhttp_filter_t *filter);
/**
 * sets per-module filter context
 */
static void vhttp_context_set_filter_context(vhttp_context_t *ctx, vhttp_filter_t *filter, void *filter_ctx);
/**
 * returns per-module context set by the on_context_init callback
 */
static void *vhttp_context_get_logger_context(vhttp_context_t *ctx, vhttp_logger_t *logger);
/*
 * return the address associated with the key in the context storage
 */
static void **vhttp_context_get_storage(vhttp_context_t *ctx, size_t *key, void (*dispose_cb)(void *));

/* built-in generators */

enum {
    /**
     * enforces the http1 protocol handler to close the connection after sending the response
     */
    vhttp_SEND_ERROR_HTTP1_CLOSE_CONNECTION = 0x1,
    /**
     * if set, does not flush the registered response headers
     */
    vhttp_SEND_ERROR_KEEP_HEADERS = 0x2,
    /**
     * indicates a broken or incomplete HTTP request, and that some fields of `vhttp_req_t` e.g., `input` might be NULL
     */
    vhttp_SEND_ERROR_BROKEN_REQUEST = 0x04
};

/**
 * Add a `date:` header to the response
 */
void vhttp_resp_add_date_header(vhttp_req_t *req);
/**
 * Sends the given string as the response. The function copies the string so that the caller can discard it immediately.
 *
 * Be careful of calling the function asynchronously, because there is a chance of the request object getting destroyed before the
 * function is being invoked.  This could happpen for example when the client abruptly closing the connection. There are two ways to
 * detect the destruction:
 *
 * * allocate a memory chunk using the request's memory pool with a destructor that you define; i.e. call `vhttp_mem_alloc_shared(
 *   &req->pool, obj_size, my_destructor)`. When the request object is destroyed, `my_destructor` will be invoked as part of the
 *   memory reclamation process.
 * * register the `stop` callback of the generator that is bound to the request. The downside of the approach is that a generator
 *   is not associated to a request until all the response headers become ready to be sent, i.e., when `vhttp_start_response` is
 *   called.
 */
void vhttp_send_inline(vhttp_req_t *req, const char *body, size_t len);
/**
 * sends the given information as an error response to the client. Uses vhttp_send_inline internally, so the same restrictions apply.
 */
void vhttp_send_error_generic(vhttp_req_t *req, int status, const char *reason, const char *body, int flags);
#define vhttp_SEND_ERROR_XXX(status)                                                                                                 \
    static inline void vhttp_send_error_##status(vhttp_req_t *req, const char *reason, const char *body, int flags)                    \
    {                                                                                                                              \
        req->conn->ctx->emitted_error_status[vhttp_STATUS_ERROR_##status]++;                                                         \
        vhttp_send_error_generic(req, status, reason, body, flags);                                                                  \
    }

vhttp_SEND_ERROR_XXX(400)
vhttp_SEND_ERROR_XXX(401)
vhttp_SEND_ERROR_XXX(403)
vhttp_SEND_ERROR_XXX(404)
vhttp_SEND_ERROR_XXX(405)
vhttp_SEND_ERROR_XXX(413)
vhttp_SEND_ERROR_XXX(416)
vhttp_SEND_ERROR_XXX(417)
vhttp_SEND_ERROR_XXX(421)
vhttp_SEND_ERROR_XXX(500)
vhttp_SEND_ERROR_XXX(502)
vhttp_SEND_ERROR_XXX(503)

/**
 * sends error response using zero timeout; can be called by output filters while processing the headers.  Uses vhttp_send_inline
 * internally, so the same restrictions apply.
 */
void vhttp_send_error_deferred(vhttp_req_t *req, int status, const char *reason, const char *body, int flags);
/**
 * sends a redirect response.  Uses (the equivalent of) vhttp_send_inline internally, so the same restrictions apply.
 */
void vhttp_send_redirect(vhttp_req_t *req, int status, const char *reason, const char *url, size_t url_len);
/**
 * handles redirect internally.
 */
void vhttp_send_redirect_internal(vhttp_req_t *req, vhttp_iovec_t method, const char *url_str, size_t url_len, int preserve_overrides);
/**
 * returns method to be used after redirection
 */
vhttp_iovec_t vhttp_get_redirect_method(vhttp_iovec_t method, int status);
/**
 * registers push path (if necessary) by parsing a Link header
 * this returns a version of `value` that removes the links that had the `x-http2-push-only` attribute
 */
vhttp_iovec_t vhttp_push_path_in_link_header(vhttp_req_t *req, const char *value, size_t value_len);
/**
 * sends 1xx response
 */
void vhttp_send_informational(vhttp_req_t *req);
/**
 *
 */
static int vhttp_req_can_stream_request(vhttp_req_t *req);
/**
 * resolves internal redirect url for dest regarding req's hostconf
 */
int vhttp_req_resolve_internal_redirect_url(vhttp_req_t *req, vhttp_iovec_t dest, vhttp_url_t *resolved);
/**
 * logs an error
 */
void vhttp_req_log_error(vhttp_req_t *req, const char *module, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void vhttp_write_error_log(vhttp_iovec_t prefix, vhttp_iovec_t msg);

/* log */

enum { vhttp_LOGCONF_ESCAPE_APACHE, vhttp_LOGCONF_ESCAPE_JSON };

/**
 * compiles a log configuration
 */
vhttp_logconf_t *vhttp_logconf_compile(const char *fmt, int escape, char *errbuf);
/**
 * disposes of a log configuration
 */
void vhttp_logconf_dispose(vhttp_logconf_t *logconf);
/**
 * logs a request
 */
char *vhttp_log_request(vhttp_logconf_t *logconf, vhttp_req_t *req, size_t *len, char *buf);

/* proxy */

/**
 * processes a request (by sending the request upstream)
 */
void vhttp__proxy_process_request(vhttp_req_t *req);

/* mime mapper */

/**
 * initializes the mimemap (the returned chunk is refcounted)
 */
vhttp_mimemap_t *vhttp_mimemap_create(void);
/**
 * clones a mimemap
 */
vhttp_mimemap_t *vhttp_mimemap_clone(vhttp_mimemap_t *src);
/**
 *
 */
void vhttp_mimemap_on_context_init(vhttp_mimemap_t *mimemap, vhttp_context_t *ctx);
/**
 *
 */
void vhttp_mimemap_on_context_dispose(vhttp_mimemap_t *mimemap, vhttp_context_t *ctx);
/**
 * returns if the map contains a dynamic type
 */
int vhttp_mimemap_has_dynamic_type(vhttp_mimemap_t *mimemap);
/**
 * sets the default mime-type
 */
void vhttp_mimemap_set_default_type(vhttp_mimemap_t *mimemap, const char *mime, vhttp_mime_attributes_t *attr);
/**
 * adds a mime-type mapping
 */
void vhttp_mimemap_define_mimetype(vhttp_mimemap_t *mimemap, const char *ext, const char *mime, vhttp_mime_attributes_t *attr);
/**
 * adds a mime-type mapping
 */
vhttp_mimemap_type_t *vhttp_mimemap_define_dynamic(vhttp_mimemap_t *mimemap, const char **exts, vhttp_globalconf_t *globalconf);
/**
 * removes a mime-type mapping
 */
void vhttp_mimemap_remove_type(vhttp_mimemap_t *mimemap, const char *ext);
/**
 * clears all mime-type mapping
 */
void vhttp_mimemap_clear_types(vhttp_mimemap_t *mimemap);
/**
 * sets the default mime-type
 */
vhttp_mimemap_type_t *vhttp_mimemap_get_default_type(vhttp_mimemap_t *mimemap);
/**
 * returns the mime-type corresponding to given extension
 */
vhttp_mimemap_type_t *vhttp_mimemap_get_type_by_extension(vhttp_mimemap_t *mimemap, vhttp_iovec_t ext);
/**
 * returns the mime-type corresponding to given mimetype
 */
vhttp_mimemap_type_t *vhttp_mimemap_get_type_by_mimetype(vhttp_mimemap_t *mimemap, vhttp_iovec_t mime, int exact_match_only);
/**
 * returns the default mime attributes given a mime type
 */
void vhttp_mimemap_get_default_attributes(const char *mime, vhttp_mime_attributes_t *attr);

/* various handlers */

/* lib/access_log.c */

typedef struct st_vhttp_access_log_filehandle_t vhttp_access_log_filehandle_t;

int vhttp_access_log_open_log(const char *path);
vhttp_access_log_filehandle_t *vhttp_access_log_open_handle(const char *path, const char *fmt, int escape);
vhttp_logger_t *vhttp_access_log_register(vhttp_pathconf_t *pathconf, vhttp_access_log_filehandle_t *handle);
void vhttp_access_log_register_configurator(vhttp_globalconf_t *conf);

/* lib/handler/server_timing.c */
void vhttp_server_timing_register(vhttp_pathconf_t *pathconf, int enforce);
void vhttp_server_timing_register_configurator(vhttp_globalconf_t *conf);

/* lib/compress.c */

enum { vhttp_COMPRESS_FLAG_PARTIAL, vhttp_COMPRESS_FLAG_FLUSH, vhttp_COMPRESS_FLAG_EOS };

/**
 * compressor context
 */
typedef struct st_vhttp_compress_context_t {
    /**
     * name used in content-encoding header
     */
    vhttp_iovec_t name;
    /**
     * compress or decompress callback (inbufs are raw buffers)
     */
    vhttp_send_state_t (*do_transform)(struct st_vhttp_compress_context_t *self, vhttp_sendvec_t *inbufs, size_t inbufcnt,
                                     vhttp_send_state_t state, vhttp_sendvec_t **outbufs, size_t *outbufcnt);
    /**
     * push buffer
     */
    char *push_buf;
} vhttp_compress_context_t;

typedef struct st_vhttp_compress_args_t {
    size_t min_size;
    struct {
        int quality; /* -1 if disabled */
    } gzip;
    struct {
        int quality; /* -1 if disabled */
    } brotli;
} vhttp_compress_args_t;

/**
 * registers the gzip/brotli encoding output filter (added by default, for now)
 */
void vhttp_compress_register(vhttp_pathconf_t *pathconf, vhttp_compress_args_t *args);
/**
 * compresses given chunk
 */
vhttp_send_state_t vhttp_compress_transform(vhttp_compress_context_t *self, vhttp_req_t *req, vhttp_sendvec_t *inbufs, size_t inbufcnt,
                                        vhttp_send_state_t state, vhttp_sendvec_t **outbufs, size_t *outbufcnt);
/**
 * instantiates the gzip compressor
 */
vhttp_compress_context_t *vhttp_compress_gzip_open(vhttp_mem_pool_t *pool, int quality);
/**
 * instantiates the gzip decompressor
 */
vhttp_compress_context_t *vhttp_compress_gunzip_open(vhttp_mem_pool_t *pool);
/**
 * instantiates the brotli compressor (only available if vhttp_USE_BROTLI is set)
 */
vhttp_compress_context_t *vhttp_compress_brotli_open(vhttp_mem_pool_t *pool, int quality, size_t estimated_cotent_length,
                                                 size_t preferred_chunk_size);
/**
 * registers the configurator for the gzip/brotli output filter
 */
void vhttp_compress_register_configurator(vhttp_globalconf_t *conf);

/* lib/handler/throttle_resp.c */
/**
 * registers the throttle response filter
 */
void vhttp_throttle_resp_register(vhttp_pathconf_t *pathconf);
/**
 * configurator
 */
void vhttp_throttle_resp_register_configurator(vhttp_globalconf_t *conf);

/* lib/errordoc.c */

typedef struct st_vhttp_errordoc_t {
    int status;
    vhttp_iovec_t url; /* can be relative */
} vhttp_errordoc_t;

/**
 * registers the errordocument output filter
 */
void vhttp_errordoc_register(vhttp_pathconf_t *pathconf, vhttp_errordoc_t *errdocs, size_t cnt);
/**
 *
 */
void vhttp_errordoc_register_configurator(vhttp_globalconf_t *conf);

/* lib/expires.c */

enum { vhttp_EXPIRES_MODE_ABSOLUTE, vhttp_EXPIRES_MODE_MAX_AGE };

typedef struct st_vhttp_expires_args_t {
    int mode;
    union {
        const char *absolute;
        uint64_t max_age;
    } data;
} vhttp_expires_args_t;

/**
 * registers a filter that adds an Expires (or Cache-Control) header
 */
void vhttp_expires_register(vhttp_pathconf_t *pathconf, vhttp_expires_args_t *args);
/**
 *
 */
void vhttp_expires_register_configurator(vhttp_globalconf_t *conf);

/* lib/fastcgi.c */

typedef struct st_vhttp_fastcgi_handler_t vhttp_fastcgi_handler_t;

#define vhttp_DEFAULT_FASTCGI_IO_TIMEOUT 30000

typedef struct st_vhttp_fastcgi_config_vars_t {
    uint64_t io_timeout;
    uint64_t keepalive_timeout; /* 0 to disable */
    vhttp_iovec_t document_root;  /* .base=NULL if not set */
    int send_delegated_uri;     /* whether to send the rewritten HTTP_HOST & REQUEST_URI by delegation, or the original */
    struct {
        void (*dispose)(vhttp_fastcgi_handler_t *handler, void *data);
        void *data;
    } callbacks;
} vhttp_fastcgi_config_vars_t;

/**
 * registers the fastcgi handler to the context
 */
vhttp_fastcgi_handler_t *vhttp_fastcgi_register(vhttp_pathconf_t *pathconf, vhttp_url_t *upstream, vhttp_fastcgi_config_vars_t *vars);
/**
 * registers the fastcgi handler to the context
 */
vhttp_fastcgi_handler_t *vhttp_fastcgi_register_by_spawnproc(vhttp_pathconf_t *pathconf, char **argv, vhttp_fastcgi_config_vars_t *vars);
/**
 * registers the configurator
 */
void vhttp_fastcgi_register_configurator(vhttp_globalconf_t *conf);

/* lib/file.c */

enum {
    vhttp_FILE_FLAG_NO_ETAG = 0x1,
    vhttp_FILE_FLAG_DIR_LISTING = 0x2,
    vhttp_FILE_FLAG_SEND_COMPRESSED = 0x4,
    vhttp_FILE_FLAG_GUNZIP = 0x8
};

typedef struct st_vhttp_file_handler_t vhttp_file_handler_t;

extern const char **vhttp_file_default_index_files;

/**
 * sends given file as the response to the client
 */
int vhttp_file_send(vhttp_req_t *req, int status, const char *reason, const char *path, vhttp_iovec_t mime_type, int flags);
/**
 * registers a handler that serves a directory of statically-served files
 * @param pathconf
 * @param virtual_path
 * @param real_path
 * @param index_files optional NULL-terminated list of of filenames to be considered as the "directory-index"
 * @param mimemap the mimemap (vhttp_mimemap_create is called internally if the argument is NULL)
 */
vhttp_file_handler_t *vhttp_file_register(vhttp_pathconf_t *pathconf, const char *real_path, const char **index_files,
                                      vhttp_mimemap_t *mimemap, int flags);
/**
 * registers a handler that serves a specific file
 * @param pathconf
 * @param virtual_path
 * @param real_path
 * @param index_files optional NULL-terminated list of of filenames to be considered as the "directory-index"
 * @param mimemap the mimemap (vhttp_mimemap_create is called internally if the argument is NULL)
 */
vhttp_handler_t *vhttp_file_register_file(vhttp_pathconf_t *pathconf, const char *real_path, vhttp_mimemap_type_t *mime_type, int flags);
/**
 * returns the associated mimemap
 */
vhttp_mimemap_t *vhttp_file_get_mimemap(vhttp_file_handler_t *handler);
/**
 * registers the configurator
 */
void vhttp_file_register_configurator(vhttp_globalconf_t *conf);

/* lib/headers.c */

enum {
    vhttp_HEADERS_CMD_NULL,
    vhttp_HEADERS_CMD_ADD,                /* adds a new header line */
    vhttp_HEADERS_CMD_APPEND,             /* adds a new header line or contenates to the existing header */
    vhttp_HEADERS_CMD_MERGE,              /* merges the value into a comma-listed values of the named header */
    vhttp_HEADERS_CMD_SET,                /* sets a header line, overwriting the existing one (if any) */
    vhttp_HEADERS_CMD_SETIFEMPTY,         /* sets a header line if empty */
    vhttp_HEADERS_CMD_UNSET,              /* removes the named header(s) */
    vhttp_HEADERS_CMD_UNSETUNLESS,        /* only keeps the named header(s) */
    vhttp_HEADERS_CMD_COOKIE_UNSET,       /* removes the named cookie(s) */
    vhttp_HEADERS_CMD_COOKIE_UNSETUNLESS, /* only keeps the named cookie(s) */
};

typedef enum vhttp_headers_command_when {
    vhttp_HEADERS_CMD_WHEN_FINAL,
    vhttp_HEADERS_CMD_WHEN_EARLY,
    vhttp_HEADERS_CMD_WHEN_ALL,
} vhttp_headers_command_when_t;

typedef struct st_vhttp_headers_command_arg_t {
    vhttp_iovec_t *name; /* maybe a token */
    vhttp_iovec_t value;
} vhttp_headers_command_arg_t;

struct st_vhttp_headers_command_t {
    int cmd;
    vhttp_headers_command_arg_t *args;
    size_t num_args;
    vhttp_headers_command_when_t when;
};

/**
 * registers a list of commands terminated by cmd==vhttp_HEADERS_CMD_NULL
 */
void vhttp_headers_register(vhttp_pathconf_t *pathconf, vhttp_headers_command_t *cmds);
/**
 * returns whether if the given name can be registered to the filter
 */
int vhttp_headers_is_prohibited_name(const vhttp_token_t *token);
/**
 * registers the configurator
 */
void vhttp_headers_register_configurator(vhttp_globalconf_t *conf);

/* lib/proxy.c */

typedef struct st_vhttp_proxy_config_vars_t {
    uint64_t io_timeout;
    uint64_t connect_timeout;
    uint64_t first_byte_timeout;
    uint64_t keepalive_timeout;
    struct {
        uint64_t name_resolution_delay;
        uint64_t connection_attempt_delay;
    } happy_eyeballs;
    unsigned preserve_host : 1;
    unsigned use_expect : 1;
    unsigned use_proxy_protocol : 1;
    unsigned tunnel_enabled : 1;
    unsigned connect_proxy_status_enabled : 1;
    unsigned support_masque_draft_03 : 1;
    /**
     * a boolean flag if set to true, instructs the proxy to close the frontend h1 connection on behalf of the upstream
     */
    unsigned forward_close_connection : 1;
    vhttp_headers_command_t *headers_cmds;
    size_t max_buffer_size;
    struct {
        uint32_t max_concurrent_streams;
        unsigned force_cleartext : 1;
    } http2;
    vhttp_httpclient_protocol_ratio_t protocol_ratio;
} vhttp_proxy_config_vars_t;

/**
 * registers the reverse proxy handler to the context
 */
void vhttp_proxy_register_reverse_proxy(vhttp_pathconf_t *pathconf, vhttp_proxy_config_vars_t *config, vhttp_socketpool_t *sockpool);
/**
 * registers the configurator
 */
void vhttp_proxy_register_configurator(vhttp_globalconf_t *conf);

/* lib/redirect.c */

typedef struct st_vhttp_redirect_handler_t vhttp_redirect_handler_t;

/**
 * registers the redirect handler to the context
 * @param pathconf
 * @param internal whether if the redirect is internal or external
 * @param status status code to be sent (e.g. 301, 303, 308, ...)
 * @param prefix prefix of the destitation URL
 */
vhttp_redirect_handler_t *vhttp_redirect_register(vhttp_pathconf_t *pathconf, int internal, int status, const char *prefix);
/**
 * registers the configurator
 */
void vhttp_redirect_register_configurator(vhttp_globalconf_t *conf);

/* lib/handler/reproxy.c */

typedef struct st_vhttp_reproxy_handler_t vhttp_reproxy_handler_t;

/**
 * registers the reproxy filter
 */
void vhttp_reproxy_register(vhttp_pathconf_t *pathconf);
/**
 * registers the configurator
 */
void vhttp_reproxy_register_configurator(vhttp_globalconf_t *conf);

/* lib/handler/connect.c */

typedef struct st_vhttp_connect_acl_entry_t {
    uint8_t allow_; /* true if allow, false if deny */
    enum { vhttp_CONNECT_ACL_ADDRESS_ANY, vhttp_CONNECT_ACL_ADDRESS_V4, vhttp_CONNECT_ACL_ADDRESS_V6 } addr_family;
    union {
        uint32_t v4;
        uint8_t v6[16];
    } addr;
    size_t addr_mask;
    uint16_t port; /* 0 indicates ANY */
} vhttp_connect_acl_entry_t;

/**
 * registers the classic connect handler to the context
 */
void vhttp_connect_register(vhttp_pathconf_t *pathconf, vhttp_proxy_config_vars_t *config, vhttp_connect_acl_entry_t *acl_entries,
                          size_t num_acl_entries);
/**
 * registers the connect-udp handler (RFC 9298) to the context
 */
void vhttp_connect_udp_register(vhttp_pathconf_t *pathconf, vhttp_proxy_config_vars_t *config, vhttp_connect_acl_entry_t *acl_entries,
                              size_t num_acl_entries);
/**
 * Parses a ACL line and stores the result in `output`. If successful, returns NULL, otherwise a string indicating the problem is
 * being returned.
 */
const char *vhttp_connect_parse_acl(vhttp_connect_acl_entry_t *output, const char *input);
/**
 * Checks if access to given target is permissible, and returns a boolean indicating the result.
 */
int vhttp_connect_lookup_acl(vhttp_connect_acl_entry_t *acl_entries, size_t num_acl_entries, struct sockaddr *target);

/* lib/handler/status.c */

/**
 * registers the status handler
 */
void vhttp_status_register(vhttp_pathconf_t *pathconf);
/**
 * registers the duration handler
 */
void vhttp_duration_stats_register(vhttp_globalconf_t *conf);
/**
 * registers the configurator
 */
void vhttp_status_register_configurator(vhttp_globalconf_t *conf);

/* lib/handler/headers_util.c */

struct headers_util_add_arg_t;

/**
 * appends a headers command to the list
 */
void vhttp_headers_append_command(vhttp_headers_command_t **cmds, int cmd, vhttp_headers_command_arg_t *args, size_t num_args,
                                vhttp_headers_command_when_t when);
/**
 * rewrite headers by the command provided
 */
void vhttp_rewrite_headers(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, vhttp_headers_command_t *cmd);

/* lib/handler/http2_debug_state.c */

/**
 * registers the http2 debug state handler
 */
void vhttp_http2_debug_state_register(vhttp_hostconf_t *hostconf, int hpack_enabled);
/**
 * registers the configurator
 */
void vhttp_http2_debug_state_register_configurator(vhttp_globalconf_t *conf);

/* lib/handler/conn_state.c */

/**
 *
 */
void vhttp_self_trace_register(vhttp_pathconf_t *conf);
/**
 *
 */
void vhttp_self_trace_register_configurator(vhttp_globalconf_t *conf);

/* lib/handler/vhttplog.c */

/**
 * registers the vhttplog handler, where vhttplog(1) connects to.
 */
void vhttp_log_register(vhttp_hostconf_t *hostconf);
/**
 * registers the vhttplog configurator.
 */
void vhttp_log_register_configurator(vhttp_globalconf_t *conf);


/* inline defs */

#ifdef vhttp_NO_64BIT_ATOMICS
extern pthread_mutex_t vhttp_conn_id_mutex;
#endif

inline const char *vhttp_conn_get_uuid(vhttp_conn_t *conn)
{
    if (conn->_uuid.is_initialized)
        return conn->_uuid.str;
    vhttp_generate_uuidv4(conn->_uuid.str);
    conn->_uuid.is_initialized = 1;
    return conn->_uuid.str;
}

inline int vhttp_conn_is_early_data(vhttp_conn_t *conn)
{
    ptls_t *tls;
    if (conn->callbacks->get_ptls == NULL)
        return 0;
    if ((tls = conn->callbacks->get_ptls(conn)) == NULL)
        return 0;
    if (ptls_handshake_is_complete(tls))
        return 0;
    return 1;
}

inline void vhttp_proceed_response(vhttp_req_t *req)
{
    if (req->_generator != NULL) {
        req->_generator->proceed(req->_generator, req);
    } else {
        req->_ostr_top->do_send(req->_ostr_top, req, NULL, 0, vhttp_SEND_STATE_FINAL);
    }
}

inline vhttp_iovec_t *vhttp_req_getenv(vhttp_req_t *req, const char *name, size_t name_len, int allocate_if_not_found)
{
    size_t i;
    for (i = 0; i != req->env.size; i += 2)
        if (vhttp_memis(req->env.entries[i].base, req->env.entries[i].len, name, name_len))
            return req->env.entries + i + 1;
    if (!allocate_if_not_found)
        return NULL;
    vhttp_vector_reserve(&req->pool, &req->env, req->env.size + 2);
    req->env.entries[req->env.size++] = vhttp_iovec_init(name, name_len);
    req->env.entries[req->env.size++] = vhttp_iovec_init(NULL, 0);
    return req->env.entries + req->env.size - 1;
}

inline void vhttp_req_unsetenv(vhttp_req_t *req, const char *name, size_t name_len)
{
    size_t i;
    for (i = 0; i != req->env.size; i += 2)
        if (vhttp_memis(req->env.entries[i].base, req->env.entries[i].len, name, name_len))
            goto Found;
    /* not found */
    return;
Found:
    memmove(req->env.entries + i, req->env.entries + i + 2, req->env.size - i - 2);
    req->env.size -= 2;
}

inline int vhttp_send_state_is_in_progress(vhttp_send_state_t s)
{
    return s == vhttp_SEND_STATE_IN_PROGRESS;
}

inline void vhttp_setup_next_ostream(vhttp_req_t *req, vhttp_ostream_t **slot)
{
    vhttp_filter_t *next;

    if (req->_next_filter_index < req->num_filters) {
        next = req->filters[req->_next_filter_index++];
        next->on_setup_ostream(next, req, slot);
    }
}

inline void vhttp_setup_next_prefilter(vhttp_req_prefilter_t *self, vhttp_req_t *req, vhttp_ostream_t **slot)
{
    vhttp_req_prefilter_t *next = self->next;

    if (next != NULL)
        next->on_setup_ostream(next, req, slot);
    else
        vhttp_setup_next_ostream(req, slot);
}

inline vhttp_timestamp_t vhttp_get_timestamp(vhttp_context_t *ctx, vhttp_mem_pool_t *pool)
{
    time_t prev_sec = ctx->_timestamp_cache.tv_at.tv_sec;
    ctx->_timestamp_cache.tv_at = vhttp_gettimeofday(ctx->loop);
    if (ctx->_timestamp_cache.tv_at.tv_sec != prev_sec)
        vhttp_context_update_timestamp_string_cache(ctx);

    vhttp_timestamp_t ts;
    ts.at = ctx->_timestamp_cache.tv_at;
    vhttp_mem_link_shared(pool, ctx->_timestamp_cache.value);
    ts.str = ctx->_timestamp_cache.value;

    return ts;
}

inline void *vhttp_context_get_handler_context(vhttp_context_t *ctx, vhttp_handler_t *handler)
{
    return ctx->_module_configs[handler->_config_slot];
}

inline void vhttp_context_set_handler_context(vhttp_context_t *ctx, vhttp_handler_t *handler, void *handler_ctx)
{
    ctx->_module_configs[handler->_config_slot] = handler_ctx;
}

inline void *vhttp_context_get_filter_context(vhttp_context_t *ctx, vhttp_filter_t *filter)
{
    return ctx->_module_configs[filter->_config_slot];
}

inline void vhttp_context_set_filter_context(vhttp_context_t *ctx, vhttp_filter_t *filter, void *filter_ctx)
{
    ctx->_module_configs[filter->_config_slot] = filter_ctx;
}

inline void *vhttp_context_get_logger_context(vhttp_context_t *ctx, vhttp_logger_t *logger)
{
    return ctx->_module_configs[logger->_config_slot];
}

inline void **vhttp_context_get_storage(vhttp_context_t *ctx, size_t *key, void (*dispose_cb)(void *))
{
    /* SIZE_MAX might not be available in case the file is included from a C++ source file */
    size_t size_max = (size_t)-1;
    if (*key == size_max)
        *key = ctx->storage.size;
    if (ctx->storage.size <= *key) {
        vhttp_vector_reserve(NULL, &ctx->storage, *key + 1);
        memset(ctx->storage.entries + ctx->storage.size, 0, (*key + 1 - ctx->storage.size) * sizeof(ctx->storage.entries[0]));
        ctx->storage.size = *key + 1;
    }

    ctx->storage.entries[*key].dispose = dispose_cb;
    return &ctx->storage.entries[*key].data;
}

static inline void vhttp_context_set_logger_context(vhttp_context_t *ctx, vhttp_logger_t *logger, void *logger_ctx)
{
    ctx->_module_configs[logger->_config_slot] = logger_ctx;
}

inline int vhttp_req_can_stream_request(vhttp_req_t *req)
{
    vhttp_handler_t *first_handler = vhttp_get_first_handler(req);
    return first_handler != NULL && first_handler->supports_request_streaming;
}

#define COMPUTE_DURATION(name, from, until)                                                                                        \
    static inline int vhttp_time_compute_##name(struct st_vhttp_req_t *req, int64_t *delta_usec)                                       \
    {                                                                                                                              \
        if (vhttp_timeval_is_null((from)) || vhttp_timeval_is_null((until))) {                                                         \
            return 0;                                                                                                              \
        }                                                                                                                          \
        *delta_usec = vhttp_timeval_subtract((from), (until));                                                                       \
        return 1;                                                                                                                  \
    }

COMPUTE_DURATION(connect_time, &req->conn->connected_at, &req->timestamps.request_begin_at)
COMPUTE_DURATION(header_time, &req->timestamps.request_begin_at,
                 vhttp_timeval_is_null(&req->timestamps.request_body_begin_at) ? &req->processed_at.at
                                                                             : &req->timestamps.request_body_begin_at)
COMPUTE_DURATION(body_time,
                 vhttp_timeval_is_null(&req->timestamps.request_body_begin_at) ? &req->processed_at.at
                                                                             : &req->timestamps.request_body_begin_at,
                 &req->processed_at.at)
COMPUTE_DURATION(request_total_time, &req->timestamps.request_begin_at, &req->processed_at.at)
COMPUTE_DURATION(process_time, &req->processed_at.at, &req->timestamps.response_start_at)
COMPUTE_DURATION(response_time, &req->timestamps.response_start_at, &req->timestamps.response_end_at)
COMPUTE_DURATION(total_time, &req->timestamps.request_begin_at, &req->timestamps.response_end_at)

COMPUTE_DURATION(proxy_idle_time, &req->timestamps.request_begin_at, &req->proxy_stats.timestamps.start_at)
COMPUTE_DURATION(proxy_connect_time, &req->proxy_stats.timestamps.start_at, &req->proxy_stats.timestamps.request_begin_at)
COMPUTE_DURATION(proxy_request_time, &req->proxy_stats.timestamps.request_begin_at, &req->proxy_stats.timestamps.request_end_at)
COMPUTE_DURATION(proxy_process_time, &req->proxy_stats.timestamps.request_end_at, &req->proxy_stats.timestamps.response_start_at)
COMPUTE_DURATION(proxy_response_time, &req->proxy_stats.timestamps.response_start_at, &req->proxy_stats.timestamps.response_end_at)
COMPUTE_DURATION(proxy_total_time, &req->proxy_stats.timestamps.request_begin_at, &req->proxy_stats.timestamps.response_end_at)

#undef COMPUTE_DURATION

#ifdef __cplusplus
}
#endif

#endif
