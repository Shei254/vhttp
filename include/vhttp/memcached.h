/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku
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
#ifndef vhttp__memcached_h
#define vhttp__memcached_h

#include <pthread.h>
#include "vhttp/memory.h"
#include "vhttp/multithread.h"

#define vhttp_MEMCACHED_ENCODE_KEY 0x1
#define vhttp_MEMCACHED_ENCODE_VALUE 0x2

typedef struct st_vhttp_memcached_context_t vhttp_memcached_context_t;
typedef struct st_vhttp_memcached_req_t vhttp_memcached_req_t;
typedef void (*vhttp_memcached_get_cb)(vhttp_iovec_t value, void *cb_data);

vhttp_memcached_context_t *vhttp_memcached_create_context(const char *host, uint16_t port, int text_protocol, size_t num_threads,
                                                      const char *prefix);

void vhttp_memcached_receiver(vhttp_multithread_receiver_t *receiver, vhttp_linklist_t *messages);

vhttp_memcached_req_t *vhttp_memcached_get(vhttp_memcached_context_t *ctx, vhttp_multithread_receiver_t *receiver, vhttp_iovec_t key,
                                       vhttp_memcached_get_cb cb, void *cb_data, int flags);

void vhttp_memcached_cancel_get(vhttp_memcached_context_t *ctx, vhttp_memcached_req_t *req);

void vhttp_memcached_set(vhttp_memcached_context_t *ctx, vhttp_iovec_t key, vhttp_iovec_t value, uint32_t expiration, int flags);

void vhttp_memcached_delete(vhttp_memcached_context_t *ctx, vhttp_iovec_t key, int flags);

#endif
