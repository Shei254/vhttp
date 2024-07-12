/*
 * Copyright (c) 2015 Daisuke Maki, DeNA Co., Ltd., Kazuho Oku
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
#include <inttypes.h>
#include "vhttp.h"
#include "vhttp/configurator.h"

struct config_t {
    int enabled;
};

struct reproxy_configurator_t {
    vhttp_configurator_t super;
    struct config_t *vars, _vars_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_reproxy(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct reproxy_configurator_t *self = (void *)cmd->configurator;

    ssize_t ret = vhttp_configurator_get_one_of(cmd, node, "OFF,ON");
    if (ret == -1)
        return -1;
    self->vars->enabled = (int)ret;

    return 0;
}

static int on_config_enter(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct reproxy_configurator_t *self = (void *)_self;

    self->vars[1] = self->vars[0];
    ++self->vars;
    return 0;
}

static int on_config_exit(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct reproxy_configurator_t *self = (void *)_self;

    if (ctx->pathconf != NULL && !vhttp_configurator_at_extension_level(ctx) && self->vars->enabled != 0)
        vhttp_reproxy_register(ctx->pathconf);

    --self->vars;
    return 0;
}

void vhttp_reproxy_register_configurator(vhttp_globalconf_t *conf)
{
    struct reproxy_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    /* reproxy: ON | OFF */
    vhttp_configurator_define_command(&c->super, "reproxy",
                                    vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_reproxy);
}
