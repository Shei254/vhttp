/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#ifndef vhttp_MRUBY_H
#define vhttp_MRUBY_H

#include "vhttp.h"
#include <mruby.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/compile.h>

#define vhttp_MRUBY_MODULE_NAME "vhttp_mruby"

enum {
    /* [0 .. vhttp_MAX_TOKENS-1] are header names */
    /* [vhttp_MAX_TOKENS .. vhttp_MAX_TOKENS*2-1] are header names in environment variable style (i.e, "HTTP_FOO_BAR") */
    vhttp_MRUBY_LIT_REQUEST_METHOD = vhttp_MAX_TOKENS * 2,
    vhttp_MRUBY_LIT_SCRIPT_NAME,
    vhttp_MRUBY_LIT_PATH_INFO,
    vhttp_MRUBY_LIT_QUERY_STRING,
    vhttp_MRUBY_LIT_SERVER_NAME,
    vhttp_MRUBY_LIT_SERVER_ADDR,
    vhttp_MRUBY_LIT_SERVER_PORT,
    vhttp_MRUBY_LIT_SERVER_PROTOCOL,
    vhttp_MRUBY_LIT_CONTENT_LENGTH,
    vhttp_MRUBY_LIT_REMOTE_ADDR,
    vhttp_MRUBY_LIT_REMOTE_PORT,
    vhttp_MRUBY_LIT_REMOTE_USER,
    vhttp_MRUBY_LIT_RACK_URL_SCHEME,
    vhttp_MRUBY_LIT_RACK_MULTITHREAD,
    vhttp_MRUBY_LIT_RACK_MULTIPROCESS,
    vhttp_MRUBY_LIT_RACK_RUN_ONCE,
    vhttp_MRUBY_LIT_RACK_HIJACK_,
    vhttp_MRUBY_LIT_RACK_INPUT,
    vhttp_MRUBY_LIT_RACK_ERRORS,
    vhttp_MRUBY_LIT_RACK_EARLY_HINTS,
    vhttp_MRUBY_LIT_SERVER_SOFTWARE,
    vhttp_MRUBY_LIT_SERVER_SOFTWARE_VALUE,
    vhttp_MRUBY_LIT_vhttp_REMAINING_DELEGATIONS,
    vhttp_MRUBY_LIT_vhttp_REMAINING_REPROCESSES,
    vhttp_MRUBY_LIT_vhttp_GET_RTT,
    vhttp_MRUBY_LIT_vhttp_IS_ECH,
    vhttp_MRUBY_PROC_EACH_TO_ARRAY,
    vhttp_MRUBY_PROC_APP_TO_FIBER,

    vhttp_MRUBY_vhttp_MODULE,
    vhttp_MRUBY_GENERATOR_CLASS,
    vhttp_MRUBY_ERROR_STREAM_CLASS,
    vhttp_MRUBY_APP_REQUEST_CLASS,
    vhttp_MRUBY_APP_INPUT_STREAM_CLASS,

    /* used by sender.c */
    vhttp_MRUBY_SENDER_PROC_EACH_TO_FIBER,

    /* used by http_request.c */
    vhttp_MRUBY_HTTP_REQUEST_CLASS,
    vhttp_MRUBY_HTTP_INPUT_STREAM_CLASS,
    vhttp_MRUBY_HTTP_EMPTY_INPUT_STREAM_CLASS,

    /* used by channel.c */
    vhttp_MRUBY_CHANNEL_CLASS,

    vhttp_MRUBY_NUM_CONSTANTS
};

typedef struct st_vhttp_mruby_config_vars_t {
    vhttp_iovec_t source;
    char *path;
    int lineno;
} vhttp_mruby_config_vars_t;

typedef struct st_vhttp_mruby_handler_t {
    vhttp_handler_t super;
    vhttp_mruby_config_vars_t config;
    vhttp_pathconf_t *pathconf;
} vhttp_mruby_handler_t;

typedef struct st_vhttp_mruby_context_t vhttp_mruby_context_t;
typedef mrb_value (*vhttp_mruby_callback_t)(vhttp_mruby_context_t *ctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                          int *run_again);
typedef vhttp_VECTOR(vhttp_mruby_callback_t) vhttp_mruby_callbacks_t;

typedef struct st_vhttp_mruby_shared_context_t {
    vhttp_context_t *ctx;
    mrb_state *mrb;
    mrb_value constants;
    struct st_vhttp_mruby_context_t *current_context;
    struct {
        mrb_sym sym_call;
        mrb_sym sym_close;
        mrb_sym sym_method;
        mrb_sym sym_headers;
        mrb_sym sym_body;
        mrb_sym sym_async;
    } symbols;
    vhttp_mruby_callbacks_t callbacks;
} vhttp_mruby_shared_context_t;

struct st_vhttp_mruby_context_t {
    vhttp_mruby_handler_t *handler;
    mrb_value proc;
    vhttp_mruby_shared_context_t *shared;
    mrb_value blocking_reqs;
    mrb_value resumers;
};

typedef struct st_vhttp_mruby_sender_t vhttp_mruby_sender_t;
typedef struct st_vhttp_mruby_http_request_context_t vhttp_mruby_http_request_context_t;
typedef struct st_vhttp_mruby_channel_context_t vhttp_mruby_channel_context_t;
typedef struct st_vhttp_mruby_generator_t vhttp_mruby_generator_t;

typedef int (*vhttp_mruby_send_response_callback_t)(vhttp_mruby_generator_t *generator, mrb_int status, mrb_value resp,
                                                  int *is_delegate);

struct st_vhttp_mruby_sender_t {
    /**
     * The body object being sent to the native side. Becomes nil on eos.
     */
    mrb_value body_obj;
    /**
     * Size of the body being sent. SIZE_MAX indicates that the number is undetermined (i.e. no Content-Length).
     */
    size_t bytes_left;
    /**
     * Initializes the subclass. called immediately after vhttp_start_response is called
     */
    void (*start)(vhttp_mruby_generator_t *generator);
    /**
     * called directly by protocol handler
     */
    void (*proceed)(vhttp_generator_t *generator, vhttp_req_t *req);
    /**
     * called when the generator is disposed
     */
    void (*dispose)(vhttp_mruby_generator_t *generator);
    /**
     * if `vhttp_send` has been closed (by passing any other flag than in-progress
     */
    unsigned char final_sent : 1;
};

typedef struct st_vhttp_mruby_error_stream_t {
    vhttp_mruby_context_t *ctx;
    vhttp_mruby_generator_t *generator;
} vhttp_mruby_error_stream_t;

struct st_vhttp_mruby_generator_t {
    vhttp_generator_t super;
    vhttp_req_t *req; /* becomes NULL once the underlying connection gets terminated */
    vhttp_mruby_context_t *ctx;
    mrb_value rack_input;
    vhttp_mruby_sender_t *sender;
    vhttp_mruby_error_stream_t *error_stream;
    struct {
        mrb_value generator;
        mrb_value error_stream;
    } refs;
};

#define vhttp_mruby_assert(mrb)                                                                                                      \
    do {                                                                                                                           \
        if (mrb->exc != NULL)                                                                                                      \
            vhttp_mruby__abort_exc(mrb, "unexpected ruby error", __FILE__, __LINE__);                                                \
    } while (0)

#define vhttp_mruby_new_str(mrb, s, l) vhttp_mruby__new_str((mrb), (s), (l), 0, __FILE__, __LINE__)
#define vhttp_mruby_new_str_static(mrb, s, l) vhttp_mruby__new_str((mrb), (s), (l), 1, __FILE__, __LINE__)

/* source files using this macro should include mruby/throw.h */
#define vhttp_MRUBY_EXEC_GUARD(block)                                                                                                \
    do {                                                                                                                           \
        struct mrb_jmpbuf *prev_jmp = mrb->jmp;                                                                                    \
        struct mrb_jmpbuf c_jmp;                                                                                                   \
        MRB_TRY(&c_jmp)                                                                                                            \
        {                                                                                                                          \
            mrb->jmp = &c_jmp;                                                                                                     \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
            mrb->jmp = prev_jmp;                                                                                                   \
        }                                                                                                                          \
        MRB_CATCH(&c_jmp)                                                                                                          \
        {                                                                                                                          \
            mrb->jmp = prev_jmp;                                                                                                   \
        }                                                                                                                          \
        MRB_END_EXC(&c_jmp);                                                                                                       \
    } while (0)

/* handler/mruby.c */
void vhttp_mruby__abort_exc(mrb_state *mrb, const char *mess, const char *file, int line);
mrb_value vhttp_mruby__new_str(mrb_state *mrb, const char *s, size_t len, int is_static, const char *file, int line);
mrb_value vhttp_mruby_to_str(mrb_state *mrb, mrb_value v);
mrb_value vhttp_mruby_to_int(mrb_state *mrb, mrb_value v);
mrb_value vhttp_mruby_eval_expr(mrb_state *mrb, const char *expr);
mrb_value vhttp_mruby_eval_expr_location(mrb_state *mrb, const char *expr, const char *path, const int lineno);
void vhttp_mruby_define_callback(mrb_state *mrb, const char *name, vhttp_mruby_callback_t callback);
mrb_value vhttp_mruby_create_data_instance(mrb_state *mrb, mrb_value class_obj, void *ptr, const mrb_data_type *type);
void vhttp_mruby_setup_globals(mrb_state *mrb);
struct RProc *vhttp_mruby_compile_code(mrb_state *mrb, vhttp_mruby_config_vars_t *config, char *errbuf);
vhttp_mruby_handler_t *vhttp_mruby_register(vhttp_pathconf_t *pathconf, vhttp_mruby_config_vars_t *config);

void vhttp_mruby_run_fiber(vhttp_mruby_context_t *ctx, mrb_value receiver, mrb_value input, int *is_delegate);
mrb_value vhttp_mruby_each_to_array(vhttp_mruby_shared_context_t *shared_ctx, mrb_value src);
int vhttp_mruby_iterate_rack_headers(vhttp_mruby_shared_context_t *shared_ctx, mrb_value headers,
                                   int (*cb)(vhttp_mruby_shared_context_t *, vhttp_iovec_t *, vhttp_iovec_t, void *), void *cb_data);
int vhttp_mruby_iterate_header_values(vhttp_mruby_shared_context_t *shared_ctx, mrb_value name, mrb_value value,
                                    int (*cb)(vhttp_mruby_shared_context_t *, vhttp_iovec_t *, vhttp_iovec_t, void *), void *cb_data);
int vhttp_mruby_iterate_native_headers(vhttp_mruby_shared_context_t *shared_ctx, vhttp_mem_pool_t *pool, vhttp_headers_t *headers,
                                     int (*cb)(vhttp_mruby_shared_context_t *, vhttp_mem_pool_t *, vhttp_header_t *, void *),
                                     void *cb_data);
int vhttp_mruby_set_response_header(vhttp_mruby_shared_context_t *shared_ctx, vhttp_iovec_t *name, vhttp_iovec_t value, void *req);

mrb_value vhttp_mruby_token_string(vhttp_mruby_shared_context_t *shared, const vhttp_token_t *token);
mrb_value vhttp_mruby_token_env_key(vhttp_mruby_shared_context_t *shared, const vhttp_token_t *token);

/* handler/mruby/sender.c */
void vhttp_mruby_sender_init_context(vhttp_mruby_shared_context_t *ctx);
/**
 * create and set new sender object corresponding the body argument. called only from send_response in mruby.c
 */
int vhttp_mruby_init_sender(vhttp_mruby_generator_t *generator, mrb_value body);
/**
 * create base sender object, called by subclasses (http_request, middleware, etc)
 */
vhttp_mruby_sender_t *vhttp_mruby_sender_create(vhttp_mruby_generator_t *generator, mrb_value body, size_t alignment, size_t sz);
/**
 * a wrapper of vhttp_send with counting and checking content-length
 */
void vhttp_mruby_sender_do_send(vhttp_mruby_generator_t *generator, vhttp_sendvec_t *bufs, size_t bufcnt, vhttp_send_state_t state);
/**
 * utility function used by sender implementations that needs buffering
 */
void vhttp_mruby_sender_do_send_buffer(vhttp_mruby_generator_t *generator, vhttp_doublebuffer_t *db, vhttp_buffer_t **input, int is_final);
/**
 * close body object, called when responding is stopped or finally disposed
 */
void vhttp_mruby_sender_close_body(vhttp_mruby_generator_t *generator);

/* handler/mruby/http_request.c */
void vhttp_mruby_http_request_init_context(vhttp_mruby_shared_context_t *ctx);
vhttp_mruby_sender_t *vhttp_mruby_http_sender_create(vhttp_mruby_generator_t *generator, mrb_value body);

/* handler/mruby/redis.c */
void vhttp_mruby_redis_init_context(vhttp_mruby_shared_context_t *ctx);

/* handler/mruby/sleep.c */
void vhttp_mruby_sleep_init_context(vhttp_mruby_shared_context_t *ctx);

/* handler/mruby/middleware.c */
void vhttp_mruby_middleware_init_context(vhttp_mruby_shared_context_t *ctx);
vhttp_mruby_sender_t *vhttp_mruby_middleware_sender_create(vhttp_mruby_generator_t *generator, mrb_value body);
vhttp_mruby_send_response_callback_t vhttp_mruby_middleware_get_send_response_callback(vhttp_mruby_context_t *ctx, mrb_value resp);

/* handler/mruby/channel.c */
void vhttp_mruby_channel_init_context(vhttp_mruby_shared_context_t *ctx);

/* handler/configurator/mruby.c */
void vhttp_mruby_register_configurator(vhttp_globalconf_t *conf);

vhttp_mruby_generator_t *vhttp_mruby_get_generator(mrb_state *mrb, mrb_value obj);
vhttp_mruby_error_stream_t *vhttp_mruby_get_error_stream(mrb_state *mrb, mrb_value obj);

#endif
