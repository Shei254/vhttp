/*
 * Copyright (c) 2017 Fastly, Inc.
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
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "vhttp/memory.h"
#include "vhttp/timerwheel.h"

#define vhttp_TIMERWHEEL_SLOTS_MASK (vhttp_TIMERWHEEL_SLOTS_PER_WHEEL - 1)

#ifndef vhttp_TIMER_VALIDATE
#define vhttp_TIMER_VALIDATE 0
#endif

#define REPORT_CORRUPT_TIMER(ctx, e, fmt, ...)                                                                                     \
    do {                                                                                                                           \
        vhttp_timerwheel_entry_t *_e = (e);                                                                                          \
        vhttp_error_printf("%s:%d:last_run=%" PRIu64 fmt ", timer(%p)={expire_at=%" PRIu64 ", cb=%p}\n", __FUNCTION__, __LINE__,     \
                         (ctx)->last_run, __VA_ARGS__, _e, _e->expire_at, _e->cb);                                                 \
    } while (0)

#define ABORT_CORRUPT_TIMER(ctx, t, fmt, ...)                                                                                      \
    do {                                                                                                                           \
        REPORT_CORRUPT_TIMER(ctx, t, fmt, __VA_ARGS__);                                                                            \
        vhttp_fatal("timerwheel");                                                                                                   \
    } while (0)

struct st_vhttp_timerwheel_t {
    /**
     * the last time vhttp_timer_run_wheel was called
     */
    uint64_t last_run;
    /**
     * maximum ticks that can be retained safely in the structure. Objects that need to be retained longer will be re-registered at
     * the highest wheel.
     */
    uint64_t max_ticks;
    /**
     * number of wheels and the wheel
     */
    size_t num_wheels;
    vhttp_linklist_t wheels[][vhttp_TIMERWHEEL_SLOTS_PER_WHEEL];
};

void vhttp_timerwheel_dump(vhttp_timerwheel_t *ctx)
{
    size_t wheel, slot;

    vhttp_error_printf("%s(%p):\n", __FUNCTION__, ctx);
    for (wheel = 0; wheel < ctx->num_wheels; wheel++) {
        for (slot = 0; slot < vhttp_TIMERWHEEL_SLOTS_PER_WHEEL; slot++) {
            vhttp_linklist_t *anchor = &ctx->wheels[wheel][slot], *l;
            for (l = anchor->next; l != anchor; l = l->next) {
                vhttp_timerwheel_entry_t *e = vhttp_STRUCT_FROM_MEMBER(vhttp_timerwheel_entry_t, _link, l);
                vhttp_error_printf("  - {wheel: %zu, slot: %zu, expires:%" PRIu64 ", self: %p, cb:%p}\n", wheel, slot, e->expire_at,
                                 e, e->cb);
            }
        }
    }
}

static size_t timer_wheel(size_t num_wheels, uint64_t delta)
{
    vhttp_BUILD_ASSERT(sizeof(unsigned long long) == 8);

    if (delta == 0)
        return 0;
    return (63 - __builtin_clzll(delta)) / vhttp_TIMERWHEEL_BITS_PER_WHEEL;
}

/* calculate slot number based on the absolute expiration time */
static size_t timer_slot(size_t wheel, uint64_t expire)
{
    return vhttp_TIMERWHEEL_SLOTS_MASK & (expire >> (wheel * vhttp_TIMERWHEEL_BITS_PER_WHEEL));
}

/**
 * returned at_max is inclusive
 */
static void calc_expire_for_slot(size_t num_wheels, uint64_t last_run, size_t wheel, size_t slot, uint64_t *at_min,
                                 uint64_t *at_max)
{
#define SPAN(i) ((uint64_t)1 << (vhttp_TIMERWHEEL_BITS_PER_WHEEL * (i))) /* returns the span of time for given wheel index */

    int adj_at_min = 0;

    *at_min = (last_run & ~(SPAN(wheel + 1) - 1)) + slot * SPAN(wheel);

    if (wheel == 0) {
        if (*at_min < last_run)
            adj_at_min = 1;
    } else {
        if (*at_min <= last_run)
            adj_at_min = 1;
    }
    if (adj_at_min)
        *at_min += SPAN(wheel + 1);

    if (wheel == num_wheels - 1) {
        *at_max = UINT64_MAX;
    } else {
        *at_max = *at_min + SPAN(wheel) - 1;
    }

#undef SPAN
}

static int validate_slot(vhttp_timerwheel_t *ctx, size_t wheel, size_t slot)
{
    vhttp_linklist_t *anchor = &ctx->wheels[wheel][slot], *link;
    uint64_t at_min, at_max;
    int success = 1;

    calc_expire_for_slot(ctx->num_wheels, ctx->last_run, wheel, slot, &at_min, &at_max);

    for (link = anchor->next; link != anchor; link = link->next) {
        vhttp_timerwheel_entry_t *e = vhttp_STRUCT_FROM_MEMBER(vhttp_timerwheel_entry_t, _link, link);
        if (!(at_min <= e->expire_at && e->expire_at <= at_max)) {
            REPORT_CORRUPT_TIMER(ctx, e, ", wheel=%zu, slot=%zu, expected_range=[%" PRIu64 ",%" PRIu64 "]", wheel, slot, at_min,
                                 at_max);
            success = 0;
        }
    }

    return success;
}

int vhttp_timerwheel_validate(vhttp_timerwheel_t *ctx)
{
    size_t wheel, slot;
    int success = 1;

    for (wheel = 0; wheel < ctx->num_wheels; ++wheel)
        for (slot = 0; slot < vhttp_TIMERWHEEL_SLOTS_PER_WHEEL; ++slot)
            if (!validate_slot(ctx, wheel, slot))
                success = 0;

    return success;
}

uint64_t vhttp_timerwheel_get_wake_at(vhttp_timerwheel_t *ctx)
{
    size_t wheel, slot;
    uint64_t at = ctx->last_run;

    for (wheel = 0; wheel < ctx->num_wheels; ++wheel) {
        uint64_t at_incr = (uint64_t)1 << (wheel * vhttp_TIMERWHEEL_BITS_PER_WHEEL);
        size_t slot_base = timer_slot(wheel, at);
        /* check current wheel from slot_base */
        for (slot = slot_base; slot < vhttp_TIMERWHEEL_SLOTS_PER_WHEEL; ++slot) {
            if (!vhttp_linklist_is_empty(&ctx->wheels[wheel][slot]))
                goto Found;
            at += at_incr;
        }
        while (1) {
            /* handle carry */
            if (wheel + 1 < ctx->num_wheels) {
                size_t wi;
                for (wi = wheel + 1; wi < ctx->num_wheels; ++wi) {
                    size_t si = timer_slot(wi, at);
                    if (!vhttp_linklist_is_empty(&ctx->wheels[wi][si]))
                        goto Found;
                    if (si != 0)
                        break;
                }
            }
            /* check current wheel from 0 to slot_base */
            if (slot_base == 0)
                break;
            for (slot = 0; slot < slot_base; ++slot) {
                if (!vhttp_linklist_is_empty(&ctx->wheels[wheel][slot]))
                    goto Found;
                at += at_incr;
            }
            at += at_incr * (vhttp_TIMERWHEEL_SLOTS_PER_WHEEL - slot_base);
            slot_base = 0;
        }
    }

    /* not found */
    return UINT64_MAX;
Found:
    return at;
}

static void link_timer(vhttp_timerwheel_t *ctx, vhttp_timerwheel_entry_t *entry)
{
    size_t wheel, slot;
    uint64_t wheel_abs = entry->expire_at;

    if (wheel_abs > ctx->last_run + ctx->max_ticks)
        wheel_abs = ctx->last_run + ctx->max_ticks;

    wheel = timer_wheel(ctx->num_wheels, wheel_abs - ctx->last_run);
    slot = timer_slot(wheel, wheel_abs);

    if (vhttp_TIMER_VALIDATE) {
        uint64_t at_min, at_max;
        calc_expire_for_slot(ctx->num_wheels, ctx->last_run, wheel, slot, &at_min, &at_max);
        if (!(at_min <= entry->expire_at && entry->expire_at <= at_max))
            ABORT_CORRUPT_TIMER(ctx, entry, ", wheel=%zu, slot=%zu, at_min=%" PRIu64 ", at_max=%" PRIu64, wheel, slot, at_min,
                                at_max);
    }

    vhttp_linklist_insert(&ctx->wheels[wheel][slot], &entry->_link);
}

/* timer wheel APIs */

/**
 * initializes a timerwheel
 */
vhttp_timerwheel_t *vhttp_timerwheel_create(size_t num_wheels, uint64_t now)
{
    vhttp_timerwheel_t *ctx = vhttp_mem_alloc(offsetof(vhttp_timerwheel_t, wheels) + sizeof(ctx->wheels[0]) * num_wheels);
    size_t i, j;

    ctx->last_run = now;
    /* max_ticks cannot be so large that the entry will be linked once more to the same slot, see the assert in `cascade` */
    ctx->max_ticks = ((uint64_t)1 << (vhttp_TIMERWHEEL_BITS_PER_WHEEL * (num_wheels - 1))) * (vhttp_TIMERWHEEL_SLOTS_PER_WHEEL - 1);
    ctx->num_wheels = num_wheels;
    for (i = 0; i < ctx->num_wheels; i++)
        for (j = 0; j < vhttp_TIMERWHEEL_SLOTS_PER_WHEEL; j++)
            vhttp_linklist_init_anchor(&ctx->wheels[i][j]);

    return ctx;
}

void vhttp_timerwheel_destroy(vhttp_timerwheel_t *ctx)
{
    size_t i, j;

    for (i = 0; i < ctx->num_wheels; ++i) {
        for (j = 0; j < vhttp_TIMERWHEEL_SLOTS_PER_WHEEL; ++j) {
            while (!vhttp_linklist_is_empty(&ctx->wheels[i][j])) {
                vhttp_timerwheel_entry_t *entry = vhttp_STRUCT_FROM_MEMBER(vhttp_timerwheel_entry_t, _link, ctx->wheels[i][j].next);
                vhttp_timerwheel_unlink(entry);
            }
        }
    }

    free(ctx);
}

/**
 * cascading happens when the lower wheel wraps around and ticks the next
 * higher wheel
 */
static void cascade_one(vhttp_timerwheel_t *ctx, size_t wheel, size_t slot)
{
    assert(wheel > 0);

    vhttp_linklist_t *s = &ctx->wheels[wheel][slot];

    while (!vhttp_linklist_is_empty(s)) {
        vhttp_timerwheel_entry_t *entry = vhttp_STRUCT_FROM_MEMBER(vhttp_timerwheel_entry_t, _link, s->next);
        if (entry->expire_at < ctx->last_run)
            ABORT_CORRUPT_TIMER(ctx, entry, ", wheel=%zu, slot=%zu", wheel, slot);
        vhttp_linklist_unlink(&entry->_link);
        link_timer(ctx, entry);
        assert(&entry->_link != s->prev); /* detect the entry reassigned to the same slot */
    }
}

static int cascade_all(vhttp_timerwheel_t *ctx, size_t wheel)
{
    int cascaded = 0;

    for (; wheel < ctx->num_wheels; ++wheel) {
        size_t slot = timer_slot(wheel, ctx->last_run);
        if (!vhttp_linklist_is_empty(&ctx->wheels[wheel][slot]))
            cascaded = 1;
        cascade_one(ctx, wheel, slot);
        if (slot != 0)
            break;
    }

    return cascaded;
}

void vhttp_timerwheel_get_expired(vhttp_timerwheel_t *ctx, uint64_t now, vhttp_linklist_t *expired)
{
    size_t wheel = 0, slot, slot_start;

    /* time might rewind if the clock is reset */
    if (now < ctx->last_run) {
        vhttp_error_printf("%s:detected rewind; last_run=%" PRIu64 ", now=%" PRIu64 "\n", __FUNCTION__, ctx->last_run, now);
        return;
    }

Redo:
    /* collect from the first slot */
    slot_start = timer_slot(wheel, ctx->last_run);
    for (slot = slot_start; slot < vhttp_TIMERWHEEL_SLOTS_PER_WHEEL; ++slot) {
        if (wheel == 0) {
            vhttp_linklist_insert_list(expired, &ctx->wheels[wheel][slot]);
            if (ctx->last_run == now)
                goto Exit;
            ++ctx->last_run;
        } else {
            if (!vhttp_linklist_is_empty(&ctx->wheels[wheel][slot])) {
                cascade_one(ctx, wheel, slot);
                assert(vhttp_linklist_is_empty(&ctx->wheels[wheel][slot]));
                wheel = 0;
                goto Redo;
            }
            ctx->last_run += 1 << (wheel * vhttp_TIMERWHEEL_BITS_PER_WHEEL);
            if (ctx->last_run > now) {
                ctx->last_run = now;
                goto Exit;
            }
        }
    }
    /* carry */
    if (cascade_all(ctx, wheel != 0 ? wheel : 1)) {
        wheel = 0;
        goto Redo;
    }
    if (slot_start != 0 || ++wheel < ctx->num_wheels)
        goto Redo;
    /* all the wheels were empty, and they all belonged to the past */
    if (ctx->last_run < now)
        ctx->last_run = now;

Exit:
    assert(ctx->last_run == now);
}

size_t vhttp_timerwheel_run(vhttp_timerwheel_t *ctx, uint64_t now)
{
    vhttp_linklist_t expired;
    size_t count = 0;

    vhttp_linklist_init_anchor(&expired);
    vhttp_timerwheel_get_expired(ctx, now, &expired);
    while (!vhttp_linklist_is_empty(&expired)) {
        vhttp_timerwheel_entry_t *entry = vhttp_STRUCT_FROM_MEMBER(vhttp_timerwheel_entry_t, _link, expired.next);
        vhttp_linklist_unlink(&entry->_link);
        entry->cb(entry);
        ++count;
    }

    return count;
}

void vhttp_timerwheel_link_abs(vhttp_timerwheel_t *ctx, vhttp_timerwheel_entry_t *entry, uint64_t at)
{
    entry->expire_at = at < ctx->last_run ? ctx->last_run : at;
    link_timer(ctx, entry);
}
