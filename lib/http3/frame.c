/*
 * Copyright (c) 2019 Fastly, Kazuho Oku
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
#include "vhttp/http3_common.h"

size_t vhttp_http3_priority_update_frame_capacity(vhttp_http3_priority_update_frame_t *frame)
{
    return 4 /* type */ + 8 /* frame length */ + 8 /* element */ + frame->value.len;
}

uint8_t *vhttp_http3_encode_priority_update_frame(uint8_t *dst, const vhttp_http3_priority_update_frame_t *frame)
{
    dst = quicly_encodev(dst, frame->element_is_push ? vhttp_HTTP3_FRAME_TYPE_PRIORITY_UPDATE_PUSH
                                                     : vhttp_HTTP3_FRAME_TYPE_PRIORITY_UPDATE_REQUEST);
    dst = quicly_encodev(dst, quicly_encodev_capacity(frame->element) + frame->value.len);
    dst = quicly_encodev(dst, frame->element);
    memcpy(dst, frame->value.base, frame->value.len);

    return dst;
}

int vhttp_http3_decode_priority_update_frame(vhttp_http3_priority_update_frame_t *frame, int is_push, const uint8_t *payload,
                                           size_t len, const char **err_desc)
{
    const uint8_t *src = payload, *end = src + len;

    frame->element_is_push = is_push;

    if (src == end)
        return vhttp_HTTP3_ERROR_FRAME;
    if ((frame->element = quicly_decodev(&src, end)) == UINT64_MAX) {
        *err_desc = "invalid PRIORITY frame";
        return vhttp_HTTP3_ERROR_FRAME;
    }
    if (frame->element_is_push) {
        if (!(!quicly_stream_is_client_initiated(frame->element) && quicly_stream_is_unidirectional(frame->element)))
            return vhttp_HTTP3_ERROR_FRAME;
    } else {
        if (!(quicly_stream_is_client_initiated(frame->element) && !quicly_stream_is_unidirectional(frame->element)))
            return vhttp_HTTP3_ERROR_FRAME;
    }
    frame->value = vhttp_iovec_init(src, end - src);

    return 0;
}

size_t vhttp_http3_goaway_frame_capacity(quicly_stream_id_t stream_or_push_id)
{
    return 1   /* type */
           + 1 /* length field. length should be less than 64, so 1 byte should be enough to represent it */
           + quicly_encodev_capacity(stream_or_push_id);
}

uint8_t *vhttp_http3_encode_goaway_frame(uint8_t *dst, quicly_stream_id_t stream_or_push_id)
{
    *dst++ = vhttp_HTTP3_FRAME_TYPE_GOAWAY;                /* type */
    *dst++ = quicly_encodev_capacity(stream_or_push_id); /* payload length */
    dst = quicly_encodev(dst, stream_or_push_id);

    return dst;
}

int vhttp_http3_decode_goaway_frame(vhttp_http3_goaway_frame_t *frame, const uint8_t *payload, size_t len, const char **err_desc)
{
    const uint8_t *src = payload, *end = src + len;

    if ((frame->stream_or_push_id = quicly_decodev(&src, end)) == UINT64_MAX)
        goto Fail;

    if (src != end) {
        /* there was an extra byte(s) after a valid QUIC variable-length integer */
        goto Fail;
    }

    return 0;

Fail:
    *err_desc = "Invalid GOAWAY frame";
    return vhttp_HTTP3_ERROR_FRAME;
}
