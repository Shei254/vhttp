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
#ifndef vhttp__uv_binding_h
#define vhttp__uv_binding_h

#include <string.h>
#include <sys/time.h>
#include <uv.h>

#if !(defined(UV_VERSION_MAJOR) && UV_VERSION_MAJOR == 1)
#error "libvhttp (libuv binding) requires libuv version 1.x.y"
#endif

typedef uv_loop_t vhttp_loop_t;

vhttp_socket_t *vhttp_uv_socket_create(uv_handle_t *handle, uv_close_cb close_cb);
vhttp_socket_t *vhttp_uv__poll_create(vhttp_loop_t *loop, int fd, uv_close_cb close_cb);

typedef struct st_vhttp_timer_t vhttp_timer_t;
typedef void (*vhttp_timer_cb)(vhttp_timer_t *timer);
struct st_vhttp_timer_t {
    uv_timer_t *uv_timer;
    int is_linked;
    vhttp_timer_cb cb;
};

static void vhttp_timer_init(vhttp_timer_t *timer, vhttp_timer_cb cb);
void vhttp_timer_link(vhttp_loop_t *l, uint64_t delay_ticks, vhttp_timer_t *timer);
static int vhttp_timer_is_linked(vhttp_timer_t *timer);
void vhttp_timer_unlink(vhttp_timer_t *timer);

/* inline definitions */

static inline struct timeval vhttp_gettimeofday(uv_loop_t *loop)
{
    struct timeval tv_at;
    gettimeofday(&tv_at, NULL);
    return tv_at;
}

static inline uint64_t vhttp_now(vhttp_loop_t *loop)
{
    return uv_now(loop);
}

static inline uint64_t vhttp_now_nanosec(vhttp_loop_t *loop)
{
    return uv_now(loop) * 1000000;
}

inline void vhttp_timer_init(vhttp_timer_t *timer, vhttp_timer_cb cb)
{
    memset(timer, 0, sizeof(*timer));
    timer->cb = cb;
}

inline int vhttp_timer_is_linked(vhttp_timer_t *entry)
{
    return entry->is_linked;
}

#endif
