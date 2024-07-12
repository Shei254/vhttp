/*
 * Copyright (c) 2017 Justin Zhu
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
#ifndef vhttp__balancer_h
#define vhttp__balancer_h

#ifdef __cplusplus
extern "C" {
#endif

#include <netdb.h>
#include "vhttp/socketpool.h"

typedef size_t (*vhttp_balancer_selector)(vhttp_balancer_t *balancer, vhttp_socketpool_target_vector_t *targets, char *tried);

typedef void (*vhttp_balancer_destroyer)(vhttp_balancer_t *balancer);

typedef struct st_vhttp_balancer_callbacks_t {
    vhttp_balancer_selector select_;
    vhttp_balancer_destroyer destroy;
} vhttp_balancer_callbacks_t;

struct st_vhttp_balancer_t {
    const vhttp_balancer_callbacks_t *callbacks;
};

/* round robin */
vhttp_balancer_t *vhttp_balancer_create_rr(void);

/* least connection */
vhttp_balancer_t *vhttp_balancer_create_lc(void);

#ifdef __cplusplus
}
#endif

#endif
