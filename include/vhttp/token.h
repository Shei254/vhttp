/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the &quot;Software&quot;), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED &quot;AS IS&quot;, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef vhttp__token_h
#define vhttp__token_h

#include "vhttp/string_.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_vhttp_token_flags_t {
    char http2_static_table_name_index; /* non-zero if any */
    unsigned char proxy_should_drop_for_req : 1;
    unsigned char proxy_should_drop_for_res : 1;
    unsigned char is_init_header_special : 1;
    unsigned char is_hpack_special : 1;
    unsigned char copy_for_push_request : 1;
    unsigned char dont_compress : 1; /* consult `vhttp_header_t:dont_compress` as well */
    unsigned char likely_to_repeat : 1;
} vhttp_token_flags_t;

/**
 * a predefined, read-only, fast variant of vhttp_iovec_t, defined in vhttp/token.h
 */
typedef struct st_vhttp_token_t {
    vhttp_iovec_t buf;
    vhttp_token_flags_t flags;
} vhttp_token_t;

/**
 * hpack static table entries
 */
typedef struct st_vhttp_hpack_static_table_entry_t {
    const vhttp_token_t *name;
    const vhttp_iovec_t value;
} vhttp_hpack_static_table_entry_t;

/**
 * qpack static tables entries
 */
typedef struct st_vhttp_qpack_static_table_entry_t {
    const vhttp_token_t *name;
    const vhttp_iovec_t value;
} vhttp_qpack_static_table_entry_t;

#ifndef vhttp_MAX_TOKENS
#define vhttp_MAX_TOKENS 100
#endif

extern vhttp_token_t vhttp__tokens[vhttp_MAX_TOKENS];
extern size_t vhttp__num_tokens;

/**
 * returns a token (an optimized subclass of vhttp_iovec_t) containing given string, or NULL if no such thing is available
 */
const vhttp_token_t *vhttp_lookup_token(const char *name, size_t len);
/**
 * returns an boolean value if given buffer is a vhttp_token_t.
 */
int vhttp_iovec_is_token(const vhttp_iovec_t *buf);

#include "vhttp/token_table.h"

#ifdef __cplusplus
}
#endif

#endif
