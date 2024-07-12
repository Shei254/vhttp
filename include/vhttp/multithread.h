/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku, Tatsuhiko Kubo
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
#ifndef vhttp__multithread_h
#define vhttp__multithread_h

#include <pthread.h>
#include "vhttp/linklist.h"
#include "vhttp/socket.h"

typedef struct st_vhttp_multithread_receiver_t vhttp_multithread_receiver_t;
typedef struct st_vhttp_multithread_queue_t vhttp_multithread_queue_t;

typedef void (*vhttp_multithread_receiver_cb)(vhttp_multithread_receiver_t *receiver, vhttp_linklist_t *messages);

struct st_vhttp_multithread_receiver_t {
    vhttp_multithread_queue_t *queue;
    vhttp_linklist_t _link;
    vhttp_linklist_t _messages;
    vhttp_multithread_receiver_cb cb;
};

typedef struct st_vhttp_multithread_message_t {
    vhttp_linklist_t link;
} vhttp_multithread_message_t;

typedef struct st_vhttp_sem_t {
    pthread_mutex_t _mutex;
    pthread_cond_t _cond;
    ssize_t _cur;
    ssize_t _capacity;
} vhttp_sem_t;

typedef struct st_vhttp_barrier_t {
    pthread_mutex_t _mutex;
    pthread_cond_t _cond;
    size_t _count;
    size_t _out_of_wait;
} vhttp_barrier_t;

/**
 * This structure is used to rate-limit the emission of error messages.
 * When something succeeds, the user calls `vhttp_error_reporter_record_success`. When something fails, the user calls
 * `vhttp_error_reporter_record_error`, along with how long the emission of the warning message should be delayed. When the delayed
 * timer expires, the cusmo callback (registered using `vhttp_ERROR_REPORTER_INITIALIZER` macro) is invoked, so that the user can emit
 * whatever message that's necessary, alongside the number of successes and errors within the delayed period.
 *
 * Fields that do not start with `_` can be directly accessed / modified by the `report_errors` callback. In other occasions,
 * modifications MUST be made through the "record" functions. Fields that start with `_` are private and must not be touched by the
 * user.
 */
typedef struct st_vhttp_error_reporter_t {
    uint64_t cur_errors;
    uint64_t prev_successes;
    uintptr_t data;
    uint64_t _total_successes;
    pthread_mutex_t _mutex;
    vhttp_timer_t _timer;
    void (*_report_errors)(struct st_vhttp_error_reporter_t *reporter, uint64_t tocal_succeses, uint64_t cur_successes);
} vhttp_error_reporter_t;

/**
 * creates a queue that is used for inter-thread communication
 */
vhttp_multithread_queue_t *vhttp_multithread_create_queue(vhttp_loop_t *loop);
/**
 * destroys the queue
 */
void vhttp_multithread_destroy_queue(vhttp_multithread_queue_t *queue);
/**
 * registers a receiver for specific type of message
 */
void vhttp_multithread_register_receiver(vhttp_multithread_queue_t *queue, vhttp_multithread_receiver_t *receiver,
                                       vhttp_multithread_receiver_cb cb);
/**
 * unregisters a receiver
 */
void vhttp_multithread_unregister_receiver(vhttp_multithread_queue_t *queue, vhttp_multithread_receiver_t *receiver);
/**
 * sends a message (or set message to NULL to just wake up the receiving thread)
 */
void vhttp_multithread_send_message(vhttp_multithread_receiver_t *receiver, vhttp_multithread_message_t *message);
/**
 * create a thread
 */
void vhttp_multithread_create_thread(pthread_t *tid, const pthread_attr_t *attr, void *(*func)(void *), void *arg);
/**
 * returns the event loop associated with provided queue
 */
vhttp_loop_t *vhttp_multithread_get_loop(vhttp_multithread_queue_t *);

/**
 * a variant of pthread_once, that does not require you to declare a callback, nor have a global variable
 */
#define vhttp_MULTITHREAD_ONCE(block)                                                                                                \
    do {                                                                                                                           \
        static volatile int lock = 0;                                                                                              \
        int lock_loaded;                                                                                                           \
        __atomic_load(&lock, &lock_loaded, __ATOMIC_ACQUIRE);                                                                      \
        if (!lock_loaded) {                                                                                                        \
            static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;                                                              \
            pthread_mutex_lock(&mutex);                                                                                            \
            if (!lock) {                                                                                                           \
                do {                                                                                                               \
                    block                                                                                                          \
                } while (0);                                                                                                       \
                __atomic_store_n(&lock, 1, __ATOMIC_RELEASE);                                                                      \
            }                                                                                                                      \
            pthread_mutex_unlock(&mutex);                                                                                          \
        }                                                                                                                          \
    } while (0)

void vhttp_sem_init(vhttp_sem_t *sem, ssize_t capacity);
void vhttp_sem_destroy(vhttp_sem_t *sem);
void vhttp_sem_wait(vhttp_sem_t *sem);
void vhttp_sem_post(vhttp_sem_t *sem);
void vhttp_sem_set_capacity(vhttp_sem_t *sem, ssize_t new_capacity);

void vhttp_barrier_init(vhttp_barrier_t *barrier, size_t count);
/**
 * Waits for all threads to enter the barrier.
 */
void vhttp_barrier_wait(vhttp_barrier_t *barrier);
int vhttp_barrier_done(vhttp_barrier_t *barrier);
void vhttp_barrier_add(vhttp_barrier_t *barrier, size_t delta);
void vhttp_barrier_dispose(vhttp_barrier_t *barrier);

void vhttp_error_reporter__on_timeout(vhttp_timer_t *timer);
#define vhttp_ERROR_REPORTER_INITIALIZER(s)                                                                                          \
    ((vhttp_error_reporter_t){                                                                                                       \
        ._mutex = PTHREAD_MUTEX_INITIALIZER, ._timer = {.cb = vhttp_error_reporter__on_timeout}, ._report_errors = (s)})
static void vhttp_error_reporter_record_success(vhttp_error_reporter_t *reporter);
/**
 * This function records an error event, sets a delayed timer (if not yet have been set), replaces the value of
 * `vhttp_error_reporter_t::data` with `new_data`, returning the old value.
 */
uintptr_t vhttp_error_reporter_record_error(vhttp_loop_t *loop, vhttp_error_reporter_t *reporter, uint64_t delay_ticks,
                                          uintptr_t new_data);

/* inline functions */

inline void vhttp_error_reporter_record_success(vhttp_error_reporter_t *reporter)
{
    __sync_fetch_and_add(&reporter->_total_successes, 1);
}

#endif
