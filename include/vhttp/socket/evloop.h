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
#ifndef vhttp__evloop_h
#define vhttp__evloop_h

#include "vhttp/linklist.h"
#include "vhttp/timerwheel.h"

#define vhttp_SOCKET_FLAG_IS_DISPOSED 0x1
#define vhttp_SOCKET_FLAG_IS_READ_READY 0x2
#define vhttp_SOCKET_FLAG_IS_WRITE_NOTIFY 0x4
#define vhttp_SOCKET_FLAG_IS_POLLED_FOR_READ 0x8
#define vhttp_SOCKET_FLAG_IS_POLLED_FOR_WRITE 0x10
#define vhttp_SOCKET_FLAG_DONT_READ 0x20
#define vhttp_SOCKET_FLAG_IS_CONNECTING 0x40
#define vhttp_SOCKET_FLAG_IS_ACCEPTED_CONNECTION 0x80
#define vhttp_SOCKET_FLAG_IS_CONNECTING_CONNECTED 0x100
/**
 * Determines if the socket has been registered to epoll. Must be preserved when setting vhttp_SOCKET_FLAG_IS_DISPOSED, as this flag
 * is used for skipping unnecessary invocations of `epoll_ctl` or for determining the `op` being specified.
 */
#define vhttp_SOCKET_FLAG__EPOLL_IS_REGISTERED 0x1000

typedef struct st_vhttp_evloop_t {
    struct st_vhttp_evloop_socket_t *_pending_as_client;
    struct st_vhttp_evloop_socket_t *_pending_as_server;
    struct {
        struct st_vhttp_evloop_socket_t *head;
        struct st_vhttp_evloop_socket_t **tail_ref;
    } _statechanged;
    uint64_t _now_millisec;
    uint64_t _now_nanosec;
    struct timeval _tv_at;
    vhttp_timerwheel_t *_timeouts;
    vhttp_sliding_counter_t exec_time_nanosec_counter;
    uint64_t run_count;
} vhttp_evloop_t;

typedef vhttp_evloop_t vhttp_loop_t;

typedef vhttp_timerwheel_entry_t vhttp_timer_t;
typedef vhttp_timerwheel_cb vhttp_timer_cb;

extern size_t vhttp_evloop_socket_max_read_size;
extern size_t vhttp_evloop_socket_max_write_size;

vhttp_socket_t *vhttp_evloop_socket_create(vhttp_evloop_t *loop, int fd, int flags);
vhttp_socket_t *vhttp_evloop_socket_accept(vhttp_socket_t *listener);
/**
 * Sets number of bytes that can be read at once (default: 1MB).
 */
void vhttp_evloop_socket_set_max_read_size(vhttp_socket_t *sock, size_t max_size);

vhttp_evloop_t *vhttp_evloop_create(void);
void vhttp_evloop_destroy(vhttp_evloop_t *loop);
/**
 * runs a event loop once. The function returns 0 if successful, or -1 if it aborts the operation due to a system call returning an
 * error (typcially due to an interrupt setting errno to EINTR). When an error is returned, the application can consult errno and
 * rerun the event loop.
 */
int vhttp_evloop_run(vhttp_evloop_t *loop, int32_t max_wait);

#define vhttp_timer_init vhttp_timerwheel_init_entry
#define vhttp_timer_is_linked vhttp_timerwheel_is_linked
static void vhttp_timer_link(vhttp_evloop_t *loop, uint64_t delay_ticks, vhttp_timer_t *timer);
#define vhttp_timer_unlink vhttp_timerwheel_unlink

/* inline definitions */

static inline struct timeval vhttp_gettimeofday(vhttp_evloop_t *loop)
{
    return loop->_tv_at;
}

static inline uint64_t vhttp_now(vhttp_evloop_t *loop)
{
    return loop->_now_millisec;
}

static inline uint64_t vhttp_now_nanosec(vhttp_evloop_t *loop)
{
    return loop->_now_nanosec;
}

static inline uint64_t vhttp_evloop_get_execution_time_millisec(vhttp_evloop_t *loop)
{
    return loop->exec_time_nanosec_counter.average / 1000000;
}

static inline uint64_t vhttp_evloop_get_execution_time_nanosec(vhttp_evloop_t *loop)
{
    return loop->exec_time_nanosec_counter.average;
}

inline void vhttp_timer_link(vhttp_evloop_t *loop, uint64_t delay_ticks, vhttp_timer_t *timer)
{
    vhttp_timerwheel_link_abs(loop->_timeouts, timer, loop->_now_millisec + delay_ticks);
}

#endif
