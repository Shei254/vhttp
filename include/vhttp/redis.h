/*
 * Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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
#ifndef vhttp__redis_h
#define vhttp__redis_h

#include "vhttp/socket.h"

struct redisAsyncContext;
struct redisReply;

extern const char vhttp_redis_error_connection[];
extern const char vhttp_redis_error_protocol[];
extern const char vhttp_redis_error_connect_timeout[];
extern const char vhttp_redis_error_command_timeout[];

typedef enum {
    vhttp_REDIS_CONNECTION_STATE_CLOSED = 0,
    vhttp_REDIS_CONNECTION_STATE_CONNECTING,
    vhttp_REDIS_CONNECTION_STATE_CONNECTED,
} vhttp_redis_connection_state_t;

typedef struct st_vhttp_redis_client_t {
    vhttp_loop_t *loop;
    vhttp_redis_connection_state_t state;
    void (*on_connect)(void);
    void (*on_close)(const char *errstr);
    uint64_t connect_timeout;
    uint64_t command_timeout;

    struct redisAsyncContext *_redis;
    vhttp_timer_t _timeout_entry;
} vhttp_redis_client_t;

typedef void (*vhttp_redis_command_cb)(struct redisReply *reply, void *cb_data, const char *errstr);

typedef enum enum_vhttp_redis_command_type_t {
    vhttp_REDIS_COMMAND_TYPE_NORMAL = 1,
    vhttp_REDIS_COMMAND_TYPE_SUBSCRIBE,
    vhttp_REDIS_COMMAND_TYPE_UNSUBSCRIBE,
    vhttp_REDIS_COMMAND_TYPE_PSUBSCRIBE,
    vhttp_REDIS_COMMAND_TYPE_PUNSUBSCRIBE,
    vhttp_REDIS_COMMAND_TYPE_MONITOR,
    vhttp_REDIS_COMMAND_TYPE_ERROR
} vhttp_redis_command_type_t;

typedef struct st_vhttp_redis_command_t {
    vhttp_redis_client_t *client;
    vhttp_redis_command_cb cb;
    void *data;
    vhttp_redis_command_type_t type;
    vhttp_timer_t _command_timeout;
} vhttp_redis_command_t;

vhttp_redis_client_t *vhttp_redis_create_client(vhttp_loop_t *loop, size_t sz);
void vhttp_redis_connect(vhttp_redis_client_t *client, const char *host, uint16_t port);
void vhttp_redis_disconnect(vhttp_redis_client_t *client);
void vhttp_redis_free(vhttp_redis_client_t *client);

vhttp_redis_command_t *vhttp_redis_command(vhttp_redis_client_t *client, vhttp_redis_command_cb cb, void *cb_data, const char *format, ...);
vhttp_redis_command_t *vhttp_redis_command_argv(vhttp_redis_client_t *client, vhttp_redis_command_cb cb, void *cb_data, int argc,
                                            const char **argv, const size_t *argvlen);

#endif
