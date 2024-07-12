/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include "vhttp.h"

extern vhttp_status_handler_t vhttp_events_status_handler;
extern vhttp_status_handler_t vhttp_requests_status_handler;
extern vhttp_status_handler_t vhttp_durations_status_handler;
extern vhttp_status_handler_t vhttp_ssl_status_handler;
extern vhttp_status_handler_t vhttp_memory_status_handler;

struct st_vhttp_status_logger_t {
    vhttp_logger_t super;
};

struct st_vhttp_root_status_handler_t {
    vhttp_handler_t super;
    vhttp_VECTOR(vhttp_multithread_receiver_t *) receivers;
};

struct st_vhttp_status_context_t {
    vhttp_context_t *ctx;
    vhttp_multithread_receiver_t receiver;
};

struct st_status_ctx_t {
    int active;
    void *ctx;
};
struct st_vhttp_status_collector_t {
    struct {
        vhttp_req_t *req;
        vhttp_multithread_receiver_t *receiver;
    } src;
    size_t num_remaining_threads_atomic;
    vhttp_VECTOR(struct st_status_ctx_t) status_ctx;
};

struct st_vhttp_status_message_t {
    vhttp_multithread_message_t super;
    struct st_vhttp_status_collector_t *collector;
};

static void collect_reqs_of_context(struct st_vhttp_status_collector_t *collector, vhttp_context_t *ctx)
{
    int i;

    for (i = 0; i < ctx->globalconf->statuses.size; i++) {
        struct st_status_ctx_t *sc = collector->status_ctx.entries + i;
        vhttp_status_handler_t *sh = ctx->globalconf->statuses.entries[i];
        if (sc->active && sh->per_thread != NULL)
            sh->per_thread(sc->ctx, ctx);
    }

    if (__sync_sub_and_fetch(&collector->num_remaining_threads_atomic, 1) == 0) {
        struct st_vhttp_status_message_t *message = vhttp_mem_alloc(sizeof(*message));
        message->super = (vhttp_multithread_message_t){{NULL}};
        message->collector = collector;
        vhttp_multithread_send_message(collector->src.receiver, &message->super);
    }
}

static void send_response(struct st_vhttp_status_collector_t *collector)
{
    static vhttp_generator_t generator = {NULL, NULL};
    vhttp_req_t *req;
    size_t nr_statuses;
    int i;
    int cur_resp = 0;

    req = collector->src.req;
    if (!req) {
        vhttp_mem_release_shared(collector);
        return;
    }

    nr_statuses = req->conn->ctx->globalconf->statuses.size;
    size_t nr_resp = nr_statuses + 2; // 2 for the footer and header
    vhttp_iovec_t resp[nr_resp];

    memset(resp, 0, sizeof(resp[0]) * nr_resp);
    resp[cur_resp++] = (vhttp_iovec_t){vhttp_STRLIT("{\n")};

    int coma_removed = 0;
    for (i = 0; i < req->conn->ctx->globalconf->statuses.size; i++) {
        vhttp_status_handler_t *sh = req->conn->ctx->globalconf->statuses.entries[i];
        if (!collector->status_ctx.entries[i].active) {
            continue;
        }
        resp[cur_resp++] = sh->final(collector->status_ctx.entries[i].ctx, req->conn->ctx->globalconf, req);
        if (resp[cur_resp - 1].len > 0 && !coma_removed) {
            /* requests come in with a leading coma, replace if with a space */
            resp[cur_resp - 1].base[0] = ' ';
            coma_removed = 1;
        }
    }
    resp[cur_resp++] = (vhttp_iovec_t){vhttp_STRLIT("\n}\n")};

    req->res.status = 200;
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CONTENT_TYPE, NULL, vhttp_STRLIT("text/plain; charset=utf-8"));
    vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CACHE_CONTROL, NULL, vhttp_STRLIT("no-cache, no-store"));
    vhttp_start_response(req, &generator);
    vhttp_send(req, resp, vhttp_memis(req->input.method.base, req->input.method.len, vhttp_STRLIT("HEAD")) ? 0 : nr_resp,
             vhttp_SEND_STATE_FINAL);
    vhttp_mem_release_shared(collector);
}

static void on_collect_notify(vhttp_multithread_receiver_t *receiver, vhttp_linklist_t *messages)
{
    struct st_vhttp_status_context_t *status_ctx = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_status_context_t, receiver, receiver);

    while (!vhttp_linklist_is_empty(messages)) {
        struct st_vhttp_status_message_t *message = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_status_message_t, super, messages->next);
        struct st_vhttp_status_collector_t *collector = message->collector;
        vhttp_linklist_unlink(&message->super.link);
        free(message);

        if (__sync_add_and_fetch(&collector->num_remaining_threads_atomic, 0) != 0) {
            collect_reqs_of_context(collector, status_ctx->ctx);
        } else {
            send_response(collector);
        }
    }
}

static void on_collector_dispose(void *_collector)
{
}

static void on_req_close(void *p)
{
    struct st_vhttp_status_collector_t *collector = *(void **)p;
    collector->src.req = NULL;
    vhttp_mem_release_shared(collector);
}

static int on_req_json(struct st_vhttp_root_status_handler_t *self, vhttp_req_t *req, vhttp_iovec_t status_list)
{
    { /* construct collector and send request to every thread */
        struct st_vhttp_status_context_t *status_ctx = vhttp_context_get_handler_context(req->conn->ctx, &self->super);
        struct st_vhttp_status_collector_t *collector = vhttp_mem_alloc_shared(NULL, sizeof(*collector), on_collector_dispose);
        size_t i;

        memset(collector, 0, sizeof(*collector));
        for (i = 0; i < req->conn->ctx->globalconf->statuses.size; i++) {
            vhttp_status_handler_t *sh;

            vhttp_vector_reserve(&req->pool, &collector->status_ctx, collector->status_ctx.size + 1);
            sh = req->conn->ctx->globalconf->statuses.entries[i];

            if (status_list.base) {
                if (!vhttp_contains_token(status_list.base, status_list.len, sh->name.base, sh->name.len, ',')) {
                    collector->status_ctx.entries[collector->status_ctx.size].active = 0;
                    goto Skip;
                }
            }
            if (sh->init) {
                collector->status_ctx.entries[collector->status_ctx.size].ctx = sh->init();
            }
            collector->status_ctx.entries[collector->status_ctx.size].active = 1;
        Skip:
            collector->status_ctx.size++;
        }
        collector->src.req = req;
        collector->src.receiver = &status_ctx->receiver;
        collector->num_remaining_threads_atomic = self->receivers.size;

        for (i = 0; i != self->receivers.size; ++i) {
            struct st_vhttp_status_message_t *message = vhttp_mem_alloc(sizeof(*message));
            *message = (struct st_vhttp_status_message_t){{{NULL}}, collector};
            vhttp_multithread_send_message(self->receivers.entries[i], &message->super);
        }

        /* collector is also retained by the on_req_close callback */
        *(struct st_vhttp_status_collector_t **)vhttp_mem_alloc_shared(&req->pool, sizeof(collector), on_req_close) = collector;
        vhttp_mem_addref_shared(collector);
    }

    return 0;
}

static int on_req(vhttp_handler_t *_self, vhttp_req_t *req)
{
    struct st_vhttp_root_status_handler_t *self = (void *)_self;
    size_t prefix_len = req->pathconf->path.len - (req->pathconf->path.base[req->pathconf->path.len - 1] == '/');
    vhttp_iovec_t local_path = vhttp_iovec_init(req->path_normalized.base + prefix_len, req->path_normalized.len - prefix_len);

    if (local_path.len == 0 || vhttp_memis(local_path.base, local_path.len, vhttp_STRLIT("/"))) {
        /* root of the handler returns HTML that renders the status */
        vhttp_iovec_t fn;
        const char *root = getenv("vhttp_ROOT");
        if (root == NULL)
            root = vhttp_TO_STR(vhttp_ROOT);
        fn = vhttp_concat(&req->pool, vhttp_iovec_init(root, strlen(root)), vhttp_iovec_init(vhttp_STRLIT("/share/vhttp/status/index.html")));
        vhttp_add_header(&req->pool, &req->res.headers, vhttp_TOKEN_CACHE_CONTROL, NULL, vhttp_STRLIT("no-cache"));
        return vhttp_file_send(req, 200, "OK", fn.base, vhttp_iovec_init(vhttp_STRLIT("text/html; charset=utf-8")), 0);
    } else if (vhttp_memis(local_path.base, local_path.len, vhttp_STRLIT("/json"))) {
        int ret;
        /* "/json" maps to the JSON API */
        vhttp_iovec_t status_list = {NULL, 0}; /* NULL means we'll show all statuses */
        if (req->query_at != SIZE_MAX && (req->path.len - req->query_at > 6)) {
            if (vhttp_memis(&req->path.base[req->query_at], 6, "?show=", 6)) {
                status_list = vhttp_iovec_init(&req->path.base[req->query_at + 6], req->path.len - req->query_at - 6);
            }
        }
        ret = on_req_json(self, req, status_list);
        return ret;
    }

    return -1;
}

static void on_context_init(vhttp_handler_t *_self, vhttp_context_t *ctx)
{
    struct st_vhttp_root_status_handler_t *self = (void *)_self;
    struct st_vhttp_status_context_t *status_ctx = vhttp_mem_alloc(sizeof(*status_ctx));

    status_ctx->ctx = ctx;
    vhttp_multithread_register_receiver(ctx->queue, &status_ctx->receiver, on_collect_notify);

    vhttp_vector_reserve(NULL, &self->receivers, self->receivers.size + 1);
    self->receivers.entries[self->receivers.size++] = &status_ctx->receiver;

    vhttp_context_set_handler_context(ctx, &self->super, status_ctx);
}

static void on_context_dispose(vhttp_handler_t *_self, vhttp_context_t *ctx)
{
    struct st_vhttp_root_status_handler_t *self = (void *)_self;
    struct st_vhttp_status_context_t *status_ctx = vhttp_context_get_handler_context(ctx, &self->super);
    size_t i;

    for (i = 0; i != self->receivers.size; ++i)
        if (self->receivers.entries[i] == &status_ctx->receiver)
            break;
    assert(i != self->receivers.size);
    memmove(self->receivers.entries + i + 1, self->receivers.entries + i, self->receivers.size - i - 1);
    --self->receivers.size;

    vhttp_multithread_unregister_receiver(ctx->queue, &status_ctx->receiver);

    free(status_ctx);
}

void vhttp_status_register(vhttp_pathconf_t *conf)
{
    struct st_vhttp_root_status_handler_t *self = (void *)vhttp_create_handler(conf, sizeof(*self));
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
    self->super.on_req = on_req;
    vhttp_config_register_status_handler(conf->global, &vhttp_requests_status_handler);
    vhttp_config_register_status_handler(conf->global, &vhttp_events_status_handler);
    vhttp_config_register_status_handler(conf->global, &vhttp_ssl_status_handler);
    vhttp_config_register_status_handler(conf->global, &vhttp_durations_status_handler);
    vhttp_config_register_status_handler(conf->global, &vhttp_memory_status_handler);
}
