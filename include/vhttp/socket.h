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
#ifndef vhttp__socket_h
#define vhttp__socket_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#ifdef __linux__
#include <linux/errqueue.h>
#endif
#include <openssl/ssl.h>
#include <openssl/opensslconf.h>
#include "picotls.h"
#include "picotls/openssl.h" /* for vhttp_CAN_OSSL_ASYNC */
#include "vhttp/cache.h"
#include "vhttp/ebpf.h"
#include "vhttp/memory.h"
#include "vhttp/openssl_backport.h"
#include "vhttp/string_.h"

#ifndef vhttp_USE_LIBUV
#if vhttp_USE_POLL || vhttp_USE_EPOLL || vhttp_USE_KQUEUE
#define vhttp_USE_LIBUV 0
#else
#define vhttp_USE_LIBUV 1
#endif
#endif

#if defined(SO_ZEROCOPY) && defined(SO_EE_ORIGIN_ZEROCOPY)
#define vhttp_USE_MSG_ZEROCOPY 1
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#define vhttp_USE_ALPN 1
#ifndef OPENSSL_NO_NEXTPROTONEG
#define vhttp_USE_NPN 1
#else
#define vhttp_USE_NPN 0
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10001000L
#define vhttp_USE_ALPN 0
#define vhttp_USE_NPN 1
#else
#define vhttp_USE_ALPN 0
#define vhttp_USE_NPN 0
#endif

#if !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL) && OPENSSL_VERSION_NUMBER >= 0x1010100fL
#define vhttp_USE_OPENSSL_CLIENT_HELLO_CB 1
#endif
#if PTLS_OPENSSL_HAVE_ASYNC && vhttp_USE_OPENSSL_CLIENT_HELLO_CB
#define vhttp_CAN_OSSL_ASYNC 1
#endif

/**
 * Maximum size of sendvec when a pull (i.e. non-raw) vector is used. Note also that bufcnt must be set to one when a pull mode
 * vector is used.
 */
#define vhttp_PULL_SENDVEC_MAX_SIZE 65536
/**
 * Maximum amount of TLS records to generate at once. Default is 4 full-sized TLS records using 32-byte tag. This value is defined
 * to be slightly greater than vhttp_PULL_SENDVEC_MAX_SIZE, so that the two buffers can recycle the same memory buffers.
 */
#define vhttp_SOCKET_DEFAULT_SSL_BUFFER_SIZE ((5 + 16384 + 32) * 4)

typedef struct st_vhttp_sliding_counter_t {
    uint64_t average;
    struct {
        uint64_t sum;
        uint64_t slots[8];
        size_t index;
    } prev;
    struct {
        uint64_t start_at;
    } cur;
} vhttp_sliding_counter_t;

static int vhttp_sliding_counter_is_running(vhttp_sliding_counter_t *counter);
static void vhttp_sliding_counter_start(vhttp_sliding_counter_t *counter, uint64_t now);
void vhttp_sliding_counter_stop(vhttp_sliding_counter_t *counter, uint64_t now);

#define vhttp_SOCKET_INITIAL_INPUT_BUFFER_SIZE 4096

#define vhttp_SESSID_CTX ((const uint8_t *)"vhttp")
#define vhttp_SESSID_CTX_LEN (sizeof("vhttp") - 1)

typedef struct st_vhttp_socket_t vhttp_socket_t;

typedef void (*vhttp_socket_cb)(vhttp_socket_t *sock, const char *err);

#if vhttp_USE_LIBUV
#include "socket/uv-binding.h"
#else
#include "socket/evloop.h"
#endif

struct st_vhttp_socket_addr_t {
    socklen_t len;
    struct sockaddr addr;
};

enum {
    vhttp_SOCKET_LATENCY_OPTIMIZATION_STATE_TBD = 0,
    vhttp_SOCKET_LATENCY_OPTIMIZATION_STATE_NEEDS_UPDATE,
    vhttp_SOCKET_LATENCY_OPTIMIZATION_STATE_DISABLED,
    vhttp_SOCKET_LATENCY_OPTIMIZATION_STATE_DETERMINED
};

typedef struct st_vhttp_sendvec_t vhttp_sendvec_t;

/**
 * Callbacks of `vhttp_sendvec_t`. Random access capability has been removed. `read_` and `send_` only provide one-pass sequential
 * access. Properties of `vhttp_sendvec_t` (e.g., `len`, `raw`) are adjusted as bytes are read / sent from the vector.
 */
typedef struct st_vhttp_sendvec_callbacks_t {
    /**
     * Mandatory callback used to load the bytes held by the vector. Returns if the operation succeeded. When false is returned, the
     * generator is considered as been error-closed by itself.  If the callback is `vhttp_sendvec_read_raw`, the data is available as
     * raw bytes in `vhttp_sendvec_t::raw`.
     */
    int (*read_)(vhttp_sendvec_t *vec, void *dst, size_t len);
    /**
     * Optional callback for sending contents of a vector directly to a socket. Returns number of bytes being sent (could be zero),
     * or, upon error, SIZE_MAX.
     */
    size_t (*send_)(vhttp_sendvec_t *vec, int sockfd, size_t len);
} vhttp_sendvec_callbacks_t;

/**
 * send vector. Unlike an ordinary `vhttp_iovec_t`, the vector has a callback that allows the sender to delay the flattening of data
 * until it becomes necessary.
 */
struct st_vhttp_sendvec_t {
    /**
     *
     */
    const vhttp_sendvec_callbacks_t *callbacks;
    /**
     * size of the vector
     */
    size_t len;
    /**
     *
     */
    union {
        char *raw;
        uint64_t cb_arg[2];
    };
};

/**
 * abstraction layer for sockets (SSL vs. TCP)
 */
struct st_vhttp_socket_t {
    void *data;
    struct st_vhttp_socket_ssl_t *ssl;
    vhttp_buffer_t *input;
    /**
     * total bytes read (above the TLS layer)
     */
    uint64_t bytes_read;
    /**
     * total bytes written (above the TLS layer)
     */
    uint64_t bytes_written;
    /**
     * boolean flag to indicate if sock is NOT being traced
     */
    unsigned _skip_tracing : 1;
    struct {
        void (*cb)(void *data);
        void *data;
    } on_close;
    struct {
        vhttp_socket_cb read;
        vhttp_socket_cb write;
    } _cb;
    struct st_vhttp_socket_addr_t *_peername;
    struct st_vhttp_socket_addr_t *_sockname;
    struct {
        size_t cnt;
        vhttp_iovec_t *bufs;
        union {
            vhttp_iovec_t *alloced_ptr;
            vhttp_iovec_t smallbufs[4];
        };
        char *flattened;
    } _write_buf;
    struct {
        uint8_t state; /* one of vhttp_SOCKET_LATENCY_STATE_* */
        uint8_t notsent_is_minimized : 1;
        size_t suggested_tls_payload_size; /* suggested TLS record payload size, or SIZE_MAX when no need to restrict */
        size_t suggested_write_size;       /* SIZE_MAX if no need to optimize for latency */
    } _latency_optimization;
    struct st_vhttp_socket_zerocopy_buffers_t *_zerocopy;
};

typedef struct st_vhttp_socket_export_t {
    int fd;
    struct st_vhttp_socket_ssl_t *ssl;
    vhttp_buffer_t *input;
} vhttp_socket_export_t;

/**
 * sets the conditions to enable the optimization
 */
typedef struct st_vhttp_socket_latency_optimization_conditions_t {
    /**
     * in milliseconds
     */
    unsigned min_rtt;
    /**
     * percent ratio
     */
    unsigned max_additional_delay;
    /**
     * in number of octets
     */
    unsigned max_cwnd;
} vhttp_socket_latency_optimization_conditions_t;

typedef void (*vhttp_socket_ssl_resumption_get_async_cb)(vhttp_socket_t *sock, vhttp_iovec_t session_id);
typedef void (*vhttp_socket_ssl_resumption_new_cb)(vhttp_socket_t *sock, vhttp_iovec_t session_id, vhttp_iovec_t session_data);
typedef void (*vhttp_socket_ssl_resumption_remove_cb)(vhttp_iovec_t session_id);

extern vhttp_buffer_mmap_settings_t vhttp_socket_buffer_mmap_settings;
extern vhttp_buffer_prototype_t vhttp_socket_buffer_prototype;

/**
 * see vhttp_SOCKET_DEFAULT_SSL_BUFFER_SIZE
 */
extern vhttp_mem_recycle_conf_t vhttp_socket_ssl_buffer_conf;
extern __thread vhttp_mem_recycle_t vhttp_socket_ssl_buffer_allocator;
extern __thread vhttp_mem_recycle_t vhttp_socket_zerocopy_buffer_allocator;
extern __thread size_t vhttp_socket_num_zerocopy_buffers_inflight;

/**
 * boolean flag indicating if kTLS should be used (when preferable)
 */
extern int vhttp_socket_use_ktls;

extern const char vhttp_socket_error_out_of_memory[];
extern const char vhttp_socket_error_io[];
extern const char vhttp_socket_error_closed[];
extern const char vhttp_socket_error_conn_fail[];
extern const char vhttp_socket_error_conn_refused[];
extern const char vhttp_socket_error_conn_timed_out[];
extern const char vhttp_socket_error_network_unreachable[];
extern const char vhttp_socket_error_host_unreachable[];
extern const char vhttp_socket_error_socket_fail[];
extern const char vhttp_socket_error_ssl_no_cert[];
extern const char vhttp_socket_error_ssl_cert_invalid[];
extern const char vhttp_socket_error_ssl_cert_name_mismatch[];
extern const char vhttp_socket_error_ssl_decode[];
extern const char vhttp_socket_error_ssl_handshake[];

/**
 * returns the loop
 */
vhttp_loop_t *vhttp_socket_get_loop(vhttp_socket_t *sock);
/**
 * detaches a socket from loop.
 */
int vhttp_socket_export(vhttp_socket_t *sock, vhttp_socket_export_t *info);
/**
 * attaches a socket onto a loop.
 */
vhttp_socket_t *vhttp_socket_import(vhttp_loop_t *loop, vhttp_socket_export_t *info);
/**
 * destroys an exported socket info.
 */
void vhttp_socket_dispose_export(vhttp_socket_export_t *info);
/**
 * closes the socket
 */
void vhttp_socket_close(vhttp_socket_t *sock);
/**
 * Schedules a callback that would be invoked when the socket becomes immediately writable
 */
void vhttp_socket_notify_write(vhttp_socket_t *sock, vhttp_socket_cb cb);
/**
 * Obtain the underlying fd of a sock struct
 */
int vhttp_socket_get_fd(vhttp_socket_t *sock);
/**
 * Set/Unset the vhttp_SOCKET_FLAG_DONT_READ flag.
 * Setting it allows to be simply notified rather than having the data
 * automatically be read.
 */
void vhttp_socket_dont_read(vhttp_socket_t *sock, int dont_read);
/**
 * connects to peer
 */
vhttp_socket_t *vhttp_socket_connect(vhttp_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, vhttp_socket_cb cb, const char **err);
/**
 * prepares for latency-optimized write and returns the number of octets that should be written, or SIZE_MAX if failed to prepare
 */
static size_t vhttp_socket_prepare_for_latency_optimized_write(vhttp_socket_t *sock,
                                                             const vhttp_socket_latency_optimization_conditions_t *conditions);
size_t vhttp_socket_do_prepare_for_latency_optimized_write(vhttp_socket_t *sock,
                                                         const vhttp_socket_latency_optimization_conditions_t *conditions);
/**
 * writes given data to socket
 * @param sock the socket
 * @param bufs an array of buffers
 * @param bufcnt length of the buffer array
 * @param cb callback to be called when write is complete
 */
void vhttp_socket_write(vhttp_socket_t *sock, vhttp_iovec_t *bufs, size_t bufcnt, vhttp_socket_cb cb);
/**
 *
 */
void vhttp_socket_sendvec(vhttp_socket_t *sock, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_socket_cb cb);
/**
 * starts polling on the socket (for read) and calls given callback when data arrives
 * @param sock the socket
 * @param cb callback to be called when data arrives
 * @note callback is called when any data arrives at the TCP level so that the
 * applications can update their timeout counters.  In other words, there is no
 * guarantee that _new_ data is available when the callback gets called (e.g.
 * in cases like receiving a partial SSL record or a corrupt TCP packet).
 */
void vhttp_socket_read_start(vhttp_socket_t *sock, vhttp_socket_cb cb);
/**
 * stops polling on the socket (for read)
 * @param sock the socket
 */
void vhttp_socket_read_stop(vhttp_socket_t *sock);
/**
 * returns a boolean value indicating whether if there is a write is under operation
 */
static int vhttp_socket_is_writing(vhttp_socket_t *sock);
/**
 * returns a boolean value indicating whether if the socket is being polled for read
 */
static int vhttp_socket_is_reading(vhttp_socket_t *sock);
/**
 * returns the length of the local address obtained (or 0 if failed)
 */
socklen_t vhttp_socket_getsockname(vhttp_socket_t *sock, struct sockaddr *sa);
/**
 * returns the length of the remote address obtained (or 0 if failed)
 */
socklen_t vhttp_socket_getpeername(vhttp_socket_t *sock, struct sockaddr *sa);
/**
 * sets the remote address (used for overriding the value)
 */
void vhttp_socket_setpeername(vhttp_socket_t *sock, struct sockaddr *sa, socklen_t len);
/**
 *
 */
ptls_t *vhttp_socket_get_ptls(vhttp_socket_t *sock);
/**
 *
 */
int vhttp_socket_can_tls_offload(vhttp_socket_t *sock);
/**
 *
 */
vhttp_iovec_t vhttp_socket_log_tcp_congestion_controller(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
vhttp_iovec_t vhttp_socket_log_tcp_delivery_rate(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
const char *vhttp_socket_get_ssl_protocol_version(vhttp_socket_t *sock);
int vhttp_socket_get_ssl_session_reused(vhttp_socket_t *sock);
const char *vhttp_socket_get_ssl_cipher(vhttp_socket_t *sock);
int vhttp_socket_get_ssl_cipher_bits(vhttp_socket_t *sock);
vhttp_iovec_t vhttp_socket_get_ssl_session_id(vhttp_socket_t *sock);
const char *vhttp_socket_get_ssl_server_name(const vhttp_socket_t *sock);
static vhttp_iovec_t vhttp_socket_log_ssl_protocol_version(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
static vhttp_iovec_t vhttp_socket_log_ssl_session_reused(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
static vhttp_iovec_t vhttp_socket_log_ssl_cipher(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
vhttp_iovec_t vhttp_socket_log_ssl_cipher_bits(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
vhttp_iovec_t vhttp_socket_log_ssl_session_id(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
static vhttp_iovec_t vhttp_socket_log_ssl_server_name(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
static vhttp_iovec_t vhttp_socket_log_ssl_negotiated_protocol(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
vhttp_iovec_t vhttp_socket_log_ssl_ech_config_id(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
vhttp_iovec_t vhttp_socket_log_ssl_ech_kem(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
vhttp_iovec_t vhttp_socket_log_ssl_ech_cipher(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
vhttp_iovec_t vhttp_socket_log_ssl_ech_cipher_bits(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
vhttp_iovec_t vhttp_socket_log_ssl_backend(vhttp_socket_t *sock, vhttp_mem_pool_t *pool);
int vhttp_socket_ssl_new_session_cb(SSL *s, SSL_SESSION *sess);

/**
 * compares socket addresses
 */
int vhttp_socket_compare_address(struct sockaddr *x, struct sockaddr *y, int check_port);
/**
 * getnameinfo (buf should be NI_MAXHOST in length), returns SIZE_MAX if failed
 */
size_t vhttp_socket_getnumerichost(const struct sockaddr *sa, socklen_t salen, char *buf);
/**
 * returns the port number, or -1 if failed
 */
int32_t vhttp_socket_getport(const struct sockaddr *sa);
/**
 * converts given error number to string representation if known, otherwise returns `default_err`
 */
const char *vhttp_socket_get_error_string(int errnum, const char *default_err);
/**
 * performs SSL handshake on a socket
 * @param sock the socket
 * @param ssl_ctx SSL context
 * @param handshake_cb callback to be called when handshake is complete
 */
void vhttp_socket_ssl_handshake(vhttp_socket_t *sock, SSL_CTX *ssl_ctx, const char *server_name, vhttp_iovec_t alpn_protos,
                              vhttp_socket_cb handshake_cb);
/**
 * resumes SSL handshake with given session data
 * @param sock the socket
 * @param session_data session data (or {NULL,0} if not available)
 */
void vhttp_socket_ssl_resume_server_handshake(vhttp_socket_t *sock, vhttp_iovec_t session_data);
/**
 * registers callbacks to be called for handling session data
 */
void vhttp_socket_ssl_async_resumption_init(vhttp_socket_ssl_resumption_get_async_cb get_cb, vhttp_socket_ssl_resumption_new_cb new_cb);
/**
 * setups the SSL context to use the async resumption
 */
void vhttp_socket_ssl_async_resumption_setup_ctx(SSL_CTX *ctx);
/**
 * returns the name of the protocol selected using either NPN or ALPN (ALPN has the precedence).
 * @param sock the socket
 */
vhttp_iovec_t vhttp_socket_ssl_get_selected_protocol(vhttp_socket_t *sock);
/**
 * returns if the socket is in early-data state (i.e. have not yet seen ClientFinished)
 */
int vhttp_socket_ssl_is_early_data(vhttp_socket_t *sock);
/**
 *
 */
struct st_ptls_context_t *vhttp_socket_ssl_get_picotls_context(SSL_CTX *ossl);
/**
 * associates a picotls context to SSL_CTX
 */
void vhttp_socket_ssl_set_picotls_context(SSL_CTX *ossl, struct st_ptls_context_t *ptls);
/**
 *
 */
vhttp_cache_t *vhttp_socket_ssl_get_session_cache(SSL_CTX *ctx);
/**
 *
 */
void vhttp_socket_ssl_set_session_cache(SSL_CTX *ctx, vhttp_cache_t *cache);
/**
 *
 */
void vhttp_socket_ssl_destroy_session_cache_entry(vhttp_iovec_t value);
/**
 * registers the protocol list to be used for ALPN
 */
void vhttp_ssl_register_alpn_protocols(SSL_CTX *ctx, const vhttp_iovec_t *protocols);
/**
 * registers the protocol list to be used for NPN
 */
void vhttp_ssl_register_npn_protocols(SSL_CTX *ctx, const char *protocols);
/**
 * Sets the DF bit if possible. Returns true when the operation was succcessful, or when the operating system does not provide the
 * necessary features. In either case, operation can continue with or without the DF bit being set.
 */
int vhttp_socket_set_df_bit(int fd, int domain);
/**
 * helper to check if socket the socket is target of tracing
 */
static int vhttp_socket_skip_tracing(vhttp_socket_t *sock);
/**
 *
 */
void vhttp_socket_set_skip_tracing(vhttp_socket_t *sock, int skip_tracing);

#if vhttp_CAN_OSSL_ASYNC
/**
 * When generating a TLS handshake signature asynchronously, it is necessary to wait for a notification on a file descriptor at
 * which point the TLS handshake machinery is to be resumed. This function sets up a callback that would be called when that
 * notification is received. The callback must invoke `vhttp_socket_async_handshake_on_notify` to do the necessary clean up, as well
 * as obtain the `data` pointer it has supplied.
 */
void vhttp_socket_start_async_handshake(vhttp_loop_t *loop, int async_fd, void *data, vhttp_socket_cb cb);
/**
 * The function to be called by the callback supplied to `vhttp_socket_start_async_handshake`. It returns the `data` pointer supplied
 * to `vhttp_socket_start_async_handshake`.
 */
void *vhttp_socket_async_handshake_on_notify(vhttp_socket_t *async_sock, const char *err);
#endif

/**
 * Initializes a send vector that refers to mutable memory region. When the `proceed` callback is invoked, it is possible for the
 * generator to reuse (or release) that memory region.
 */
void vhttp_sendvec_init_raw(vhttp_sendvec_t *vec, const void *base, size_t len);
/**
 *
 */
int vhttp_sendvec_read_raw(vhttp_sendvec_t *vec, void *dst, size_t len);

/**
 * GC resources
 */
void vhttp_socket_clear_recycle(int full);
/**
 *
 */
int vhttp_socket_recycle_is_empty(void);

/**
 * This is a thin wrapper around sendfile (2) that hides the differences between various OS implementations.
 * @return number of bytes written (zero is a valid value indicating that the send buffer is full), or SIZE_MAX on error
 */
size_t vhttp_sendfile(int sockfd, int filefd, off_t off, size_t len);

/**
 * Prepares eBPF maps. Requires root privileges and thus should be called before dropping the privileges. Returns a boolean
 * indicating if operation succeeded.
 */
int vhttp_socket_ebpf_setup(void);
/**
 * Function to lookup if the connection is tagged for special treatment. The result is a union of `vhttp_EBPF_FLAGS_*`.
 */
uint64_t vhttp_socket_ebpf_lookup_flags(vhttp_loop_t *loop, int (*init_key)(vhttp_ebpf_map_key_t *key, void *cbdata), void *cbdata);
/**
 *
 */
uint64_t vhttp_socket_ebpf_lookup_flags_sni(vhttp_loop_t *loop, uint64_t flags, const char *server_name, size_t server_name_len);
/**
 * function for initializing the ebpf lookup key from raw information
 */
int vhttp_socket_ebpf_init_key_raw(vhttp_ebpf_map_key_t *key, int sock_type, struct sockaddr *local, struct sockaddr *remote);
/**
 * callback for initializing the ebpf lookup key from `vhttp_socket_t`
 */
int vhttp_socket_ebpf_init_key(vhttp_ebpf_map_key_t *key, void *sock);

#ifdef OPENSSL_IS_BORINGSSL
/**
 * returns SSL_[gs]et_ext_data slot used to store `ptls_async_job_t` for handling async TLS handshake signature generation
 */
int vhttp_socket_boringssl_get_async_job_index(void);
/**
 * If async resumption is in flight. When true is returned the TLS handshake is going to be discarded, and therefore the async
 * signature calculation callback should return failure rather than starting the calculation.
 */
int vhttp_socket_boringssl_async_resumption_in_flight(SSL *ssl);
#endif

/* inline defs */

inline int vhttp_socket_is_writing(vhttp_socket_t *sock)
{
    return sock->_cb.write != NULL;
}

inline int vhttp_socket_is_reading(vhttp_socket_t *sock)
{
    return sock->_cb.read != NULL;
}

inline size_t vhttp_socket_prepare_for_latency_optimized_write(vhttp_socket_t *sock,
                                                             const vhttp_socket_latency_optimization_conditions_t *conditions)
{
    switch (sock->_latency_optimization.state) {
    case vhttp_SOCKET_LATENCY_OPTIMIZATION_STATE_TBD:
    case vhttp_SOCKET_LATENCY_OPTIMIZATION_STATE_NEEDS_UPDATE:
        return vhttp_socket_do_prepare_for_latency_optimized_write(sock, conditions);
    default:
        return sock->_latency_optimization.suggested_write_size;
    }
}

inline vhttp_iovec_t vhttp_socket_log_ssl_protocol_version(vhttp_socket_t *sock, vhttp_mem_pool_t *pool)
{
    (void)pool;
    const char *s = vhttp_socket_get_ssl_protocol_version(sock);
    return s != NULL ? vhttp_iovec_init(s, strlen(s)) : vhttp_iovec_init(NULL, 0);
}

inline vhttp_iovec_t vhttp_socket_log_ssl_session_reused(vhttp_socket_t *sock, vhttp_mem_pool_t *pool)
{
    (void)pool;
    switch (vhttp_socket_get_ssl_session_reused(sock)) {
    case 0:
        return vhttp_iovec_init(vhttp_STRLIT("0"));
    case 1:
        return vhttp_iovec_init(vhttp_STRLIT("1"));
    default:
        return vhttp_iovec_init(NULL, 0);
    }
}

inline vhttp_iovec_t vhttp_socket_log_ssl_cipher(vhttp_socket_t *sock, vhttp_mem_pool_t *pool)
{
    (void)pool;
    const char *s = vhttp_socket_get_ssl_cipher(sock);
    return s != NULL ? vhttp_iovec_init(s, strlen(s)) : vhttp_iovec_init(NULL, 0);
}

inline vhttp_iovec_t vhttp_socket_log_ssl_server_name(vhttp_socket_t *sock, vhttp_mem_pool_t *pool)
{
    (void)pool;
    const char *s = vhttp_socket_get_ssl_server_name(sock);
    return s != NULL ? vhttp_iovec_init(s, strlen(s)) : vhttp_iovec_init(NULL, 0);
}

inline vhttp_iovec_t vhttp_socket_log_ssl_negotiated_protocol(vhttp_socket_t *sock, vhttp_mem_pool_t *pool)
{
    (void)pool;
    return vhttp_socket_ssl_get_selected_protocol(sock);
}

inline int vhttp_sliding_counter_is_running(vhttp_sliding_counter_t *counter)
{
    return counter->cur.start_at != 0;
}

inline void vhttp_sliding_counter_start(vhttp_sliding_counter_t *counter, uint64_t now)
{
    counter->cur.start_at = now;
}

inline int vhttp_socket_skip_tracing(vhttp_socket_t *sock)
{
    return sock->_skip_tracing;
}

#ifdef __cplusplus
}
#endif

#endif
