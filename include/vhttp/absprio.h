/*
 * Copyright (c) 2019 Fastly
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
#ifndef vhttp__absprio_h
#define vhttp__absprio_h

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define vhttp_ABSPRIO_DEFAULT_URGENCY 3
#define vhttp_ABSPRIO_NUM_URGENCY_LEVELS 8

typedef struct vhttp_absprio_t {
    uint8_t urgency : 3;
    uint8_t incremental : 1;
} vhttp_absprio_t;

extern vhttp_absprio_t vhttp_absprio_default;

void vhttp_absprio_parse_priority(const char *s, size_t len, vhttp_absprio_t *prio);
/**
 * Convert urgency value in absolute priority header to HTTP2 weight, having Chromium as a client in mind.
 */
static uint16_t vhttp_absprio_urgency_to_chromium_weight(uint8_t urgency);

/* inline functions */

inline uint16_t vhttp_absprio_urgency_to_chromium_weight(uint8_t urgency)
{
    uint16_t weight;
    assert(urgency < vhttp_ABSPRIO_NUM_URGENCY_LEVELS);
    /* formula excerpted from:
     * https://quiche.googlesource.com/quiche/+/8cbe7bfa5c6efa7a42652e36fabf8d21879894be/spdy/core/spdy_protocol.cc#50 */
    const float ksteps = 255.9f / (float)(vhttp_ABSPRIO_NUM_URGENCY_LEVELS - 1);
    weight = (uint16_t)(ksteps * ((vhttp_ABSPRIO_NUM_URGENCY_LEVELS - 1) - urgency)) + 1;
    return weight;
}

#endif
