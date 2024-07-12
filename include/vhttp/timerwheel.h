/*
 * Copyright (c) 2017 Fastly Inc., Ltd.
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
#ifndef vhttp__timerwheel_h
#define vhttp__timerwheel_h

#include "vhttp/linklist.h"

#define vhttp_TIMERWHEEL_BITS_PER_WHEEL 5
#define vhttp_TIMERWHEEL_SLOTS_PER_WHEEL (1 << vhttp_TIMERWHEEL_BITS_PER_WHEEL)

typedef struct st_vhttp_timerwheel_t vhttp_timerwheel_t;

struct st_vhttp_timerwheel_entry_t;

typedef void (*vhttp_timerwheel_cb)(struct st_vhttp_timerwheel_entry_t *entry);

typedef struct st_vhttp_timerwheel_entry_t {
    vhttp_linklist_t _link;
    uint64_t expire_at; /* absolute expiration time*/
    vhttp_timerwheel_cb cb;
} vhttp_timerwheel_entry_t;

/**
 * initializes a timer
 */
static void vhttp_timerwheel_init_entry(vhttp_timerwheel_entry_t *entry, vhttp_timerwheel_cb cb);
/**
 * activates a timer
 */
void vhttp_timerwheel_link_abs(vhttp_timerwheel_t *ctx, vhttp_timerwheel_entry_t *entry, uint64_t at);
/**
 * disactivates a timer
 */
static void vhttp_timerwheel_unlink(vhttp_timerwheel_entry_t *entry);
/**
 * returns whether a timer is active
 */
static int vhttp_timerwheel_is_linked(vhttp_timerwheel_entry_t *entry);

/**
 * creates a timerwheel
 */
vhttp_timerwheel_t *vhttp_timerwheel_create(size_t num_wheels, uint64_t now);
/**
 * destroys a timerwheel
 */
void vhttp_timerwheel_destroy(vhttp_timerwheel_t *ctx);
/**
 * display the contents of the timerwheel
 */
void vhttp_timerwheel_dump(vhttp_timerwheel_t *ctx);
/**
 * validates the timerwheel and returns the result as a boolean value
 */
int vhttp_timerwheel_validate(vhttp_timerwheel_t *ctx);
/**
 * find out the time ramaining until the next timer triggers
 */
uint64_t vhttp_timerwheel_get_wake_at(vhttp_timerwheel_t *ctx);
/**
 * collects the expired entries and returns them back to `expired`. Application must call vhttp_timer_run to fire them.
 */
void vhttp_timerwheel_get_expired(vhttp_timerwheel_t *ctx, uint64_t now, vhttp_linklist_t *expired);
/**
 * runs the expired timers
 */
size_t vhttp_timerwheel_run(vhttp_timerwheel_t *ctx, uint64_t now);

/* inline definitions */

inline void vhttp_timerwheel_init_entry(vhttp_timerwheel_entry_t *entry, vhttp_timerwheel_cb cb)
{
    *entry = (vhttp_timerwheel_entry_t){{NULL, NULL}, 0, cb};
}

inline int vhttp_timerwheel_is_linked(vhttp_timerwheel_entry_t *entry)
{
    return vhttp_linklist_is_linked(&entry->_link);
}

inline void vhttp_timerwheel_unlink(vhttp_timerwheel_entry_t *entry)
{
    if (vhttp_linklist_is_linked(&entry->_link))
        vhttp_linklist_unlink(&entry->_link);
}

#endif
