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
#include <string.h>
#include "vhttp.h"
#include "vhttp/configurator.h"

struct headers_configurator_t {
    vhttp_configurator_t super;
    vhttp_headers_command_t **cmds, *_cmd_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_enter(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct headers_configurator_t *self = (void *)_self;

    self->cmds[1] = self->cmds[0];
    if (self->cmds[1] != NULL)
        vhttp_mem_addref_shared(self->cmds[1]);

    ++self->cmds;
    return 0;
}

static int on_config_exit(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct headers_configurator_t *self = (void *)_self;

    if (ctx->pathconf != NULL && !vhttp_configurator_at_extension_level(ctx) && *self->cmds != NULL) {
        if (*self->cmds != NULL)
            vhttp_mem_addref_shared(*self->cmds);
        vhttp_headers_register(ctx->pathconf, *self->cmds);
    }

    if (*self->cmds != NULL)
        vhttp_mem_release_shared(*self->cmds);
    --self->cmds;
    return 0;
}

static vhttp_headers_command_t **get_headers_commands(vhttp_configurator_t *_self)
{
    struct headers_configurator_t *self = (void *)_self;
    return self->cmds;
}

void vhttp_headers_register_configurator(vhttp_globalconf_t *conf)
{
    struct headers_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    vhttp_configurator_define_headers_commands(conf, &c->super, "header", get_headers_commands);
    c->cmds = c->_cmd_stack;
}
