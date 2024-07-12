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
#include <errno.h>
#include "vhttp/redis.h"
#include "vhttp/hiredis_.h"
#include "vhttp/socket.h"

const char vhttp_redis_error_connection[] = "Connection Error";
const char vhttp_redis_error_protocol[] = "Protocol Error";
const char vhttp_redis_error_connect_timeout[] = "Connection Timeout";
const char vhttp_redis_error_command_timeout[] = "Command Timeout";

struct st_redis_socket_data_t {
    redisAsyncContext *context;
    const char *errstr;
    vhttp_socket_t *socket;
};

static void attach_loop(redisAsyncContext *ac, vhttp_loop_t *loop);

static void invoke_deferred(vhttp_redis_client_t *client, uint64_t tick, vhttp_timer_t *entry, vhttp_timer_cb cb)
{
    entry->cb = cb;
    vhttp_timer_link(client->loop, tick, entry);
}

static void close_and_detach_connection(vhttp_redis_client_t *client, const char *errstr)
{
    assert(client->_redis != NULL);
    client->state = vhttp_REDIS_CONNECTION_STATE_CLOSED;
    if (client->on_close != NULL)
        client->on_close(errstr);

    client->_redis->data = NULL;
    client->_redis = NULL;
    vhttp_timer_unlink(&client->_timeout_entry);
}

static void disconnect(vhttp_redis_client_t *client, const char *errstr)
{
    assert(client->state != vhttp_REDIS_CONNECTION_STATE_CLOSED);
    assert(client->_redis != NULL);

    redisAsyncContext *redis = client->_redis;
    struct st_redis_socket_data_t *data = redis->ev.data;
    data->errstr = errstr;
    close_and_detach_connection(client, errstr);
    redisAsyncFree(redis); /* immediately call all callbacks of pending commands with nil replies */
}

static const char *get_error(const redisAsyncContext *redis)
{
    switch (redis->err) {
    case REDIS_OK:
        return NULL;
    case REDIS_ERR_IO:
        /* hiredis internally checks socket error and set errno */
        if (errno == ETIMEDOUT) {
            return vhttp_redis_error_connect_timeout;
        } else {
            return vhttp_redis_error_connection;
        }
    case REDIS_ERR_EOF:
        return vhttp_redis_error_connection;
    case REDIS_ERR_PROTOCOL:
        return vhttp_redis_error_protocol;
    case REDIS_ERR_OOM:
    case REDIS_ERR_OTHER:
        return redis->errstr;
    default:
        vhttp_fatal("FIXME");
    }
}

static void on_connect(const redisAsyncContext *redis, int status)
{
    vhttp_redis_client_t *client = (vhttp_redis_client_t *)redis->data;
    if (client == NULL)
        return;

    if (status != REDIS_OK) {
        close_and_detach_connection(client, vhttp_redis_error_connection);
        return;
    }
    vhttp_timer_unlink(&client->_timeout_entry);

    client->state = vhttp_REDIS_CONNECTION_STATE_CONNECTED;
    if (client->on_connect != NULL)
        client->on_connect();
}

static void on_disconnect(const redisAsyncContext *redis, int status)
{
    vhttp_redis_client_t *client = (vhttp_redis_client_t *)redis->data;
    if (client == NULL)
        return;

    close_and_detach_connection(client, get_error(redis));
}

static void on_connect_timeout(vhttp_timer_t *entry)
{
    vhttp_redis_client_t *client = vhttp_STRUCT_FROM_MEMBER(vhttp_redis_client_t, _timeout_entry, entry);
    assert((client->_redis->c.flags & REDIS_CONNECTED) == 0);
    assert(client->state != vhttp_REDIS_CONNECTION_STATE_CLOSED);

    disconnect(client, vhttp_redis_error_connect_timeout);
}

vhttp_redis_client_t *vhttp_redis_create_client(vhttp_loop_t *loop, size_t sz)
{
    vhttp_redis_client_t *client = vhttp_mem_alloc(sz);
    memset(client, 0, sz);

    client->loop = loop;
    client->state = vhttp_REDIS_CONNECTION_STATE_CLOSED;
    vhttp_timer_init(&client->_timeout_entry, on_connect_timeout);

    return client;
}

void vhttp_redis_connect(vhttp_redis_client_t *client, const char *host, uint16_t port)
{
    if (client->state != vhttp_REDIS_CONNECTION_STATE_CLOSED) {
        return;
    }

    redisAsyncContext *redis = redisAsyncConnect(host, port);
    if (redis == NULL) {
        vhttp_fatal("no memory");
    }

    client->_redis = redis;
    client->_redis->data = client;
    client->state = vhttp_REDIS_CONNECTION_STATE_CONNECTING;

    attach_loop(redis, client->loop);
    redisAsyncSetConnectCallback(redis, on_connect);
    redisAsyncSetDisconnectCallback(redis, on_disconnect);

    if (redis->err != REDIS_OK) {
        /* some connection failures can be detected at this time */
        disconnect(client, vhttp_redis_error_connection);
        return;
    }

    if (client->connect_timeout != 0)
        vhttp_timer_link(client->loop, client->connect_timeout, &client->_timeout_entry);
}

void vhttp_redis_disconnect(vhttp_redis_client_t *client)
{
    if (client->state != vhttp_REDIS_CONNECTION_STATE_CLOSED)
        disconnect(client, NULL);
}

static void dispose_command(vhttp_redis_command_t *command)
{
    vhttp_timer_unlink(&command->_command_timeout);
    free(command);
}

static void handle_reply(vhttp_redis_command_t *command, redisReply *reply, const char *errstr)
{
    if (command->cb != NULL)
        command->cb(reply, command->data, errstr);

    switch (command->type) {
    case vhttp_REDIS_COMMAND_TYPE_SUBSCRIBE:
    case vhttp_REDIS_COMMAND_TYPE_PSUBSCRIBE:
        if (reply != NULL && reply->type == REDIS_REPLY_ARRAY) {
            char *unsub = command->type == vhttp_REDIS_COMMAND_TYPE_SUBSCRIBE ? "unsubscribe" : "punsubscribe";
            if (strncasecmp(reply->element[0]->str, unsub, reply->element[0]->len) == 0) {
                dispose_command(command);
            } else {
                /* (p)subscribe commands doesn't get freed until (p)unsubscribe or disconnect */
            }
        } else {
            dispose_command(command);
        }
        break;
    default:
        dispose_command(command);
    }
}

static void on_command(redisAsyncContext *redis, void *_reply, void *privdata)
{
    redisReply *reply = (redisReply *)_reply;
    vhttp_redis_command_t *command = (vhttp_redis_command_t *)privdata;
    const char *errstr = ((struct st_redis_socket_data_t *)redis->ev.data)->errstr;
    if (errstr == NULL)
        errstr = get_error(redis);
    handle_reply(command, reply, errstr);
}

static void on_command_timeout(vhttp_timer_t *entry)
{
    vhttp_redis_command_t *command = vhttp_STRUCT_FROM_MEMBER(vhttp_redis_command_t, _command_timeout, entry);

    /* invoke disconnect to finalize inflight commands */
    disconnect(command->client, vhttp_redis_error_command_timeout);
}

static vhttp_redis_command_t *create_command(vhttp_redis_client_t *client, vhttp_redis_command_cb cb, void *cb_data,
                                           vhttp_redis_command_type_t type)
{
    vhttp_redis_command_t *command = vhttp_mem_alloc(sizeof(vhttp_redis_command_t));
    *command = (vhttp_redis_command_t){NULL};
    command->client = client;
    command->cb = cb;
    command->data = cb_data;
    command->type = type;
    vhttp_timer_init(&command->_command_timeout, on_command_timeout);

    if (client->command_timeout != 0 && (type == vhttp_REDIS_COMMAND_TYPE_NORMAL || type == vhttp_REDIS_COMMAND_TYPE_UNSUBSCRIBE ||
                                         type == vhttp_REDIS_COMMAND_TYPE_PUNSUBSCRIBE))
        vhttp_timer_link(client->loop, client->command_timeout, &command->_command_timeout);

    return command;
}

static void send_command(vhttp_redis_client_t *client, vhttp_redis_command_t *command, const char *cmd, size_t len)
{
    if (cmd == NULL) {
        handle_reply(command, NULL, "Failed to create command");
        return;
    }

    if (client->state == vhttp_REDIS_CONNECTION_STATE_CLOSED) {
        handle_reply(command, NULL, vhttp_redis_error_connection);
        return;
    }

    if (command->type == vhttp_REDIS_COMMAND_TYPE_MONITOR) {
        /* monitor command implementation in hiredis asynchronous API is absolutely dangerous, so don't use it! */
        handle_reply(command, NULL, "Unsupported command");
        return;
    }

    int ret = redisAsyncFormattedCommand(client->_redis, on_command, command, cmd, len);
    if (ret != REDIS_OK) {
        handle_reply(command, NULL, "Failed to send command");
    }
}

/*
  hiredis doesn't expose any information about the command, so parse here.
  this function assumes that formatted is NULL-terminated
 */
static vhttp_redis_command_type_t detect_command_type(const char *formatted)
{
#define CHECK(c)                                                                                                                   \
    if (c == NULL)                                                                                                                 \
    return vhttp_REDIS_COMMAND_TYPE_ERROR

    char *p = (char *)formatted;
    CHECK(p);

    assert(p[0] == '*');

    p = strchr(p, '$');
    CHECK(p);
    p = strchr(p, '\n');
    CHECK(p);
    ++p;
    CHECK(p);

#define MATCH(c, target) strncasecmp(c, target, sizeof(target) - 1) == 0
    if (MATCH(p, "subscribe\r\n"))
        return vhttp_REDIS_COMMAND_TYPE_SUBSCRIBE;
    if (MATCH(p, "unsubscribe\r\n"))
        return vhttp_REDIS_COMMAND_TYPE_UNSUBSCRIBE;
    if (MATCH(p, "psubscribe\r\n"))
        return vhttp_REDIS_COMMAND_TYPE_PSUBSCRIBE;
    if (MATCH(p, "punsubscribe\r\n"))
        return vhttp_REDIS_COMMAND_TYPE_PUNSUBSCRIBE;
    if (MATCH(p, "monitor\r\n"))
        return vhttp_REDIS_COMMAND_TYPE_MONITOR;
#undef MATCH
    return vhttp_REDIS_COMMAND_TYPE_NORMAL;
#undef CHECK
}

vhttp_redis_command_t *vhttp_redis_command(vhttp_redis_client_t *client, vhttp_redis_command_cb cb, void *cb_data, const char *format, ...)
{
    char *cmd;
    int len;
    va_list ap;
    va_start(ap, format);
    len = redisvFormatCommand(&cmd, format, ap);
    va_end(ap);
    if (len <= 0) {
        cmd = NULL;
        len = 0;
    }

    vhttp_redis_command_t *command = create_command(client, cb, cb_data, detect_command_type(cmd));
    send_command(client, command, cmd, len);
    free(cmd);
    return command;
}

vhttp_redis_command_t *vhttp_redis_command_argv(vhttp_redis_client_t *client, vhttp_redis_command_cb cb, void *cb_data, int argc,
                                            const char **argv, const size_t *argvlen)
{
    sds sdscmd;
    int len;
    len = redisFormatSdsCommandArgv(&sdscmd, argc, argv, argvlen);
    if (len < 0) {
        sdscmd = NULL;
        len = 0;
    }

    vhttp_redis_command_t *command = create_command(client, cb, cb_data, detect_command_type(sdscmd));
    send_command(client, command, sdscmd, len);
    sdsfree(sdscmd);
    return command;
}

void vhttp_redis_free(vhttp_redis_client_t *client)
{
    if (client->state != vhttp_REDIS_CONNECTION_STATE_CLOSED)
        disconnect(client, NULL);
    vhttp_timer_unlink(&client->_timeout_entry);
    free(client);
}

/* redis socket adapter */

static void on_read(vhttp_socket_t *sock, const char *err)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)sock->data;
    redisAsyncHandleRead(p->context);
}

static void on_write(vhttp_socket_t *sock, const char *err)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)sock->data;
    redisAsyncHandleWrite(p->context);
}

static void socket_add_read(void *privdata)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    vhttp_socket_read_start(p->socket, on_read);
}

static void socket_del_read(void *privdata)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    vhttp_socket_read_stop(p->socket);
}

static void socket_add_write(void *privdata)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    if (!vhttp_socket_is_writing(p->socket)) {
        vhttp_socket_notify_write(p->socket, on_write);
    }
}

static void socket_cleanup(void *privdata)
{
    struct st_redis_socket_data_t *p = (struct st_redis_socket_data_t *)privdata;
    vhttp_socket_close(p->socket);
    p->context->c.fd = -1; /* prevent hiredis from closing fd twice */
    free(p);
}

static void attach_loop(redisAsyncContext *ac, vhttp_loop_t *loop)
{
    redisContext *c = &(ac->c);

    struct st_redis_socket_data_t *p = vhttp_mem_alloc(sizeof(*p));
    *p = (struct st_redis_socket_data_t){NULL};

    ac->ev.addRead = socket_add_read;
    ac->ev.delRead = socket_del_read;
    ac->ev.addWrite = socket_add_write;
    ac->ev.cleanup = socket_cleanup;
    ac->ev.data = p;

#if vhttp_USE_LIBUV
    p->socket = vhttp_uv__poll_create(loop, c->fd, (uv_close_cb)free);
#else
    p->socket = vhttp_evloop_socket_create(loop, c->fd, vhttp_SOCKET_FLAG_DONT_READ);
#endif

    p->socket->data = p;
    p->context = ac;
}
