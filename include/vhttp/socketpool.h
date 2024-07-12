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
#ifndef vhttp__socket_pool_h
#define vhttp__socket_pool_h

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "vhttp/linklist.h"
#include "vhttp/multithread.h"
#include "vhttp/socket.h"
#include "vhttp/url.h"

typedef enum en_vhttp_socketpool_target_type_t {
    vhttp_SOCKETPOOL_TYPE_NAMED,
    vhttp_SOCKETPOOL_TYPE_SOCKADDR
} vhttp_socketpool_target_type_t;

/**
 * TODO: support subclassing for adding balancer-specific properties
 */
typedef struct st_vhttp_socketpool_target_conf_t {
    /**
     * weight - 1 for load balancer, where weight is an integer within range [1, 256]
     */
    uint8_t weight_m1;
} vhttp_socketpool_target_conf_t;

#define vhttp_SOCKETPOOL_TARGET_MAX_WEIGHT 256

typedef struct st_vhttp_socketpool_target_t {
    /**
     * target URL
     */
    vhttp_url_t url;
    /**
     * target type (extracted from url)
     */
    vhttp_socketpool_target_type_t type;
    /**
     * peer address (extracted from url)
     */
    union {
        /* used to specify servname passed to getaddrinfo */
        vhttp_iovec_t named_serv;
        /* if type is sockaddr, the `host` is not resolved but is used for TLS SNI and hostname verification */
        struct {
            struct sockaddr_storage bytes;
            socklen_t len;
        } sockaddr;
    } peer;
    /**
     * per-target lb configuration
     */
    vhttp_socketpool_target_conf_t conf;

    /**
     * the per-target portion of vhttp_socketpool_t::_shared
     */
    struct {
        vhttp_linklist_t sockets;
        /**
         * number of connections being _leased_ to the applications (i.e. not including the number of connections being pooled).
         * Synchronous operation must be used to access the variable.
         */
        size_t leased_count;
    } _shared;
} vhttp_socketpool_target_t;

typedef vhttp_VECTOR(vhttp_socketpool_target_t *) vhttp_socketpool_target_vector_t;

typedef struct st_vhttp_balancer_t vhttp_balancer_t;

typedef struct st_vhttp_socketpool_t {

    /* read-only vars */
    vhttp_socketpool_target_vector_t targets;
    size_t capacity;
    uint64_t timeout; /* in milliseconds */
    struct {
        vhttp_loop_t *loop;
        vhttp_timer_t timeout;
    } _interval_cb;
    SSL_CTX *_ssl_ctx;

    /**
     * variables shared between threads. Unless otherwise noted, the mutex should be acquired before accessing them.
     */
    struct {
        pthread_mutex_t mutex;
        /**
         * list of struct pool_entry_t
         */
        vhttp_linklist_t sockets;
        /**
         * number of connections governed by the pool, includes sockets being pool and the ones trying to connect. Synchronous
         * operation must be used to access the variable.
         */
        size_t count;
        /**
         * number of pooled connections governed by the pool
         */
        size_t pooled_count;
    } _shared;

    /* load balancer */
    vhttp_balancer_t *balancer;
} vhttp_socketpool_t;

typedef struct st_vhttp_socketpool_connect_request_t vhttp_socketpool_connect_request_t;

typedef void (*vhttp_socketpool_connect_cb)(vhttp_socket_t *sock, const char *errstr, void *data, vhttp_url_t *url);
/**
 * initializes a specific socket pool
 */
void vhttp_socketpool_init_specific(vhttp_socketpool_t *pool, size_t capacity, vhttp_socketpool_target_t **targets, size_t num_targets,
                                  vhttp_balancer_t *balancer);
/**
 * initializes a global socket pool
 */
void vhttp_socketpool_init_global(vhttp_socketpool_t *pool, size_t capacity);
/**
 * disposes of a socket pool
 */
void vhttp_socketpool_dispose(vhttp_socketpool_t *pool);
/**
 * if the socket is a global pool
 */
int vhttp_socketpool_is_global(vhttp_socketpool_t *pool);
/**
 * create a target. If lb_target_conf is NULL, a default target conf would be created.
 */
vhttp_socketpool_target_t *vhttp_socketpool_create_target(vhttp_url_t *origin, vhttp_socketpool_target_conf_t *lb_target_conf);
/**
 * destroy a target
 */
void vhttp_socketpool_destroy_target(vhttp_socketpool_target_t *target);
/**
 *
 */
static uint64_t vhttp_socketpool_get_timeout(vhttp_socketpool_t *pool);
/**
 *
 */
static void vhttp_socketpool_set_timeout(vhttp_socketpool_t *pool, uint64_t msec);
/**
 *
 */
void vhttp_socketpool_set_ssl_ctx(vhttp_socketpool_t *pool, SSL_CTX *ssl_ctx);
/**
 * associates a loop
 */
void vhttp_socketpool_register_loop(vhttp_socketpool_t *pool, vhttp_loop_t *loop);
/**
 * unregisters the associated loop
 */
void vhttp_socketpool_unregister_loop(vhttp_socketpool_t *pool, vhttp_loop_t *loop);
/**
 * connects to the peer (or returns a pooled connection)
 */
void vhttp_socketpool_connect(vhttp_socketpool_connect_request_t **_req, vhttp_socketpool_t *pool, vhttp_url_t *url, vhttp_loop_t *loop,
                            vhttp_multithread_receiver_t *getaddr_receiver, vhttp_iovec_t alpn_protos, vhttp_socketpool_connect_cb cb,
                            void *data);
/**
 * cancels a connect request
 */
void vhttp_socketpool_cancel_connect(vhttp_socketpool_connect_request_t *req);
/**
 * returns an idling socket to the socket pool
 */
int vhttp_socketpool_return(vhttp_socketpool_t *pool, vhttp_socket_t *sock);
/**
 * detach a socket from the socket pool
 */
void vhttp_socketpool_detach(vhttp_socketpool_t *pool, vhttp_socket_t *sock);
/**
 * determines if a socket belongs to the socket pool
 */
static int vhttp_socketpool_is_owned_socket(vhttp_socketpool_t *pool, vhttp_socket_t *sock);

/* inline defs */

inline uint64_t vhttp_socketpool_get_timeout(vhttp_socketpool_t *pool)
{
    return pool->timeout;
}

inline void vhttp_socketpool_set_timeout(vhttp_socketpool_t *pool, uint64_t msec)
{
    pool->timeout = msec;
}

inline int vhttp_socketpool_is_owned_socket(vhttp_socketpool_t *pool, vhttp_socket_t *sock)
{
    return sock->on_close.data == pool;
}

int vhttp_socketpool_can_keepalive(vhttp_socketpool_t *pool);

#ifdef __cplusplus
}
#endif

#endif
