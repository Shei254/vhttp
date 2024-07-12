/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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

struct st_headers_filter_t {
    vhttp_filter_t super;
    vhttp_headers_command_t *cmds;
};

struct st_headers_early_hints_handler_t {
    vhttp_handler_t super;
    vhttp_headers_command_t *cmds;
};

struct st_headers_early_hints_sender_t {
    vhttp_req_t *req;
    vhttp_headers_command_t *cmds;
    vhttp_timer_t deferred_timeout_entry;
};

static void on_setup_ostream(vhttp_filter_t *_self, vhttp_req_t *req, vhttp_ostream_t **slot)
{
    struct st_headers_filter_t *self = (void *)_self;
    vhttp_headers_command_t *cmd;

    for (cmd = self->cmds; cmd->cmd != vhttp_HEADERS_CMD_NULL; ++cmd) {
        if (cmd->when != vhttp_HEADERS_CMD_WHEN_EARLY)
            vhttp_rewrite_headers(&req->pool, &req->res.headers, cmd);
    }

    vhttp_setup_next_ostream(req, slot);
}

static void on_informational(vhttp_filter_t *_self, vhttp_req_t *req)
{
    struct st_headers_filter_t *self = (void *)_self;
    vhttp_headers_command_t *cmd;

    if (req->res.status != 103)
        return;

    for (cmd = self->cmds; cmd->cmd != vhttp_HEADERS_CMD_NULL; ++cmd) {
        if (cmd->when != vhttp_HEADERS_CMD_WHEN_FINAL)
            vhttp_rewrite_headers(&req->pool, &req->res.headers, cmd);
    }
}

static void on_sender_deferred_timeout(vhttp_timer_t *entry)
{
    struct st_headers_early_hints_sender_t *sender =
        vhttp_STRUCT_FROM_MEMBER(struct st_headers_early_hints_sender_t, deferred_timeout_entry, entry);

    if (sender->req->res.status != 0)
        return;

    sender->req->res.status = 103;

    /* expect on_informational will be called and applies headers commands */
    vhttp_send_informational(sender->req);
}

static void on_sender_dispose(void *_sender)
{
    struct st_headers_early_hints_sender_t *sender = (struct st_headers_early_hints_sender_t *)_sender;
    if (vhttp_timer_is_linked(&sender->deferred_timeout_entry))
        vhttp_timer_unlink(&sender->deferred_timeout_entry);
}

static int on_req(vhttp_handler_t *_handler, vhttp_req_t *req)
{
    struct st_headers_early_hints_handler_t *handler = (void *)_handler;

    struct st_headers_early_hints_sender_t *sender = vhttp_mem_alloc_shared(&req->pool, sizeof(*sender), on_sender_dispose);
    sender->req = req;
    sender->cmds = handler->cmds;
    vhttp_timer_init(&sender->deferred_timeout_entry, on_sender_deferred_timeout);
    vhttp_timer_link(req->conn->ctx->loop, 0, &sender->deferred_timeout_entry);

    return -1;
}

static int requires_early_hints_handler(struct st_headers_filter_t *self)
{
    vhttp_headers_command_t *cmd;
    for (cmd = self->cmds; cmd->cmd != vhttp_HEADERS_CMD_NULL; ++cmd) {
        if (cmd->cmd != vhttp_HEADERS_CMD_UNSET && cmd->when != vhttp_HEADERS_CMD_WHEN_FINAL)
            return 1;
    }
    return 0;
}

void vhttp_headers_register(vhttp_pathconf_t *pathconf, vhttp_headers_command_t *cmds)
{
    struct st_headers_filter_t *self = (void *)vhttp_create_filter(pathconf, sizeof(*self));

    self->super.on_setup_ostream = on_setup_ostream;
    self->super.on_informational = on_informational;
    self->cmds = cmds;

    if (requires_early_hints_handler(self)) {
        struct st_headers_early_hints_handler_t *handler = (void *)vhttp_create_handler(pathconf, sizeof(*handler));
        handler->cmds = cmds;
        handler->super.on_req = on_req;

        /* move this handler to first */
        memmove(pathconf->handlers.entries + 1, pathconf->handlers.entries,
                sizeof(vhttp_handler_t *) * (pathconf->handlers.size - 1));
        pathconf->handlers.entries[0] = &handler->super;
    }
}

int vhttp_headers_is_prohibited_name(const vhttp_token_t *token)
{
    /* prohibit connection-specific headers */
    if (token == vhttp_TOKEN_CONNECTION || token == vhttp_TOKEN_CONTENT_LENGTH || token == vhttp_TOKEN_TRANSFER_ENCODING)
        return 1;
    /* prohibit headers added at protocol layer */
    if (token == vhttp_TOKEN_DATE || token == vhttp_TOKEN_SERVER)
        return 1;
    /* all others are permitted */
    return 0;
}
