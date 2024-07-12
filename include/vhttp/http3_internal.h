/*
 * Copyright (c) 2019 Fastly, Kazuho
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
#ifndef vhttp__http3_internal_h
#define vhttp__http3_internal_h

#include "khash.h"
#include "quicly.h"
#include "vhttp/memory.h"

KHASH_MAP_INIT_INT(vhttp_quic_idmap, vhttp_quic_conn_t *);
KHASH_MAP_INIT_INT64(vhttp_quic_acceptmap, vhttp_quic_conn_t *);

struct st_vhttp_http3_egress_unistream_t {
    /**
     * back pointer
     */
    quicly_stream_t *quic;
    /**
     *
     */
    vhttp_buffer_t *sendbuf;
};

#endif
