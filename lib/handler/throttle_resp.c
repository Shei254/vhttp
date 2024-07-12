/*
 * Copyright (c) 2016 Justin Zhu
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
#include <stdlib.h>
#include "vhttp.h"

typedef struct st_throttle_resp_t {
    vhttp_ostream_t super;
    vhttp_timer_t timeout_entry;
    struct {
        uint64_t at;
        ssize_t bytes_left;
    } window;
    vhttp_req_t *req;
    size_t bytes_per_sec;
    struct {
        vhttp_VECTOR(vhttp_sendvec_t) bufs;
        vhttp_send_state_t stream_state;
    } state;
} throttle_resp_t;

/**
 * Given current deficit (`bytes_left` which would be negative) and bytes_per_sec, returns when the deficit would become
 * non-negative.
 */
static uint64_t calc_delay(ssize_t bytes_left, size_t bytes_per_sec)
{
    return (-bytes_left * (uint64_t)1000 + bytes_per_sec - 1) / bytes_per_sec;
}

static void real_send(throttle_resp_t *self)
{
    uint64_t now = vhttp_now(self->req->conn->ctx->loop);

    /* if time has changed since previous invocation, update window */
    if (self->window.at < now) {
        /* burst rate (after upstream remains silent) is limited to 1-second worth of data */
        uint64_t addition = (self->bytes_per_sec * (now - self->window.at)) / 1000;
        if (addition > self->bytes_per_sec)
            addition = self->bytes_per_sec;
        self->window.bytes_left += addition;
        self->window.at = now;
    }

    /* schedule the timer for delayed invocation, if window is negative at this moment */
    if (self->window.bytes_left < 0) {
        uint64_t delay = calc_delay(self->window.bytes_left, self->bytes_per_sec);
        assert(delay > 0);
        vhttp_timer_link(self->req->conn->ctx->loop, delay, &self->timeout_entry);
        return;
    }

    /* adjust window and send */
    for (size_t i = 0; i < self->state.bufs.size; i++)
        self->window.bytes_left -= self->state.bufs.entries[i].len;
    vhttp_ostream_send_next(&self->super, self->req, self->state.bufs.entries, self->state.bufs.size, self->state.stream_state);
}

static void on_timer(vhttp_timer_t *entry)
{
    throttle_resp_t *self = vhttp_STRUCT_FROM_MEMBER(throttle_resp_t, timeout_entry, entry);
    real_send(self);
}

static void on_send(vhttp_ostream_t *_self, vhttp_req_t *req, vhttp_sendvec_t *inbufs, size_t inbufcnt, vhttp_send_state_t state)
{
    throttle_resp_t *self = (void *)_self;

    assert(!vhttp_timer_is_linked(&self->timeout_entry));

    /* save state */
    vhttp_vector_reserve(&req->pool, &self->state.bufs, inbufcnt);
    for (size_t i = 0; i < inbufcnt; ++i) {
        self->state.bufs.entries[i] = inbufs[i];
    }
    self->state.bufs.size = inbufcnt;
    self->state.stream_state = state;

    real_send(self);
}

static void on_stop(vhttp_ostream_t *_self, vhttp_req_t *req)
{
    throttle_resp_t *self = (void *)_self;
    if (vhttp_timer_is_linked(&self->timeout_entry))
        vhttp_timer_unlink(&self->timeout_entry);
}

static void on_setup_ostream(vhttp_filter_t *self, vhttp_req_t *req, vhttp_ostream_t **slot)
{
    throttle_resp_t *throttle;
    size_t bytes_per_sec;

    /* only handle 200 OK with content */
    if (req->res.status != 200)
        goto Next;
    if (vhttp_memis(req->input.method.base, req->input.method.len, vhttp_STRLIT("HEAD")))
        goto Next;

    { /* obtain the rate from X-Traffic header field and delete the header field, or skip */
        ssize_t xt_index;
        if ((xt_index = vhttp_find_header(&req->res.headers, vhttp_TOKEN_X_TRAFFIC, -1)) == -1)
            goto Next;
        char *buf = req->res.headers.entries[xt_index].value.base;
        if (vhttp_UNLIKELY((bytes_per_sec = vhttp_strtosizefwd(&buf, req->res.headers.entries[xt_index].value.len)) == SIZE_MAX))
            goto Next;
        vhttp_delete_header(&req->res.headers, xt_index);
    }

    /* instantiate the ostream filter */
    throttle = (void *)vhttp_add_ostream(req, vhttp_ALIGNOF(*throttle), sizeof(*throttle), slot);
    throttle->super.do_send = on_send;
    throttle->super.stop = on_stop;
    vhttp_timer_init(&throttle->timeout_entry, on_timer);
    throttle->window.at = vhttp_now(req->conn->ctx->loop);
    throttle->window.bytes_left = 0;
    throttle->req = req;
    throttle->bytes_per_sec = bytes_per_sec;
    memset(&throttle->state.bufs, 0, sizeof(throttle->state.bufs));
    throttle->state.stream_state = vhttp_SEND_STATE_IN_PROGRESS;

    { /* reduce `preferred_chunk_size` so that we'd be sending one chunk every 100ms */
        size_t chunk_size = bytes_per_sec / 10;
        if (chunk_size < 4096)
            chunk_size = 4096;
        if (req->preferred_chunk_size > chunk_size)
            req->preferred_chunk_size = chunk_size;
    }

    slot = &throttle->super.next;

Next:
    vhttp_setup_next_ostream(req, slot);
}

void vhttp_throttle_resp_register(vhttp_pathconf_t *pathconf)
{
    vhttp_filter_t *self = vhttp_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
