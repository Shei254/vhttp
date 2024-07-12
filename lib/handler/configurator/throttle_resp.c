/*
 * Copyright (c) 2016 Justin Zhu
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
#include "vhttp/configurator.h"

struct throttle_resp_config_vars_t {
    int on;
};

struct throttle_resp_configurator_t {
    vhttp_configurator_t super;
    struct throttle_resp_config_vars_t *vars, _vars_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_throttle_resp(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct throttle_resp_configurator_t *self = (void *)cmd->configurator;

    if ((self->vars->on = (int)vhttp_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;
    return 0;
}

static int on_config_enter(vhttp_configurator_t *configurator, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct throttle_resp_configurator_t *self = (void *)configurator;

    ++self->vars;
    self->vars[0] = self->vars[-1];
    return 0;
}

static int on_config_exit(vhttp_configurator_t *configurator, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct throttle_resp_configurator_t *self = (void *)configurator;

    if (ctx->pathconf != NULL && !vhttp_configurator_at_extension_level(ctx) && self->vars->on)
        vhttp_throttle_resp_register(ctx->pathconf);

    --self->vars;
    return 0;
}

void vhttp_throttle_resp_register_configurator(vhttp_globalconf_t *conf)
{
    struct throttle_resp_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    vhttp_configurator_define_command(&c->super, "throttle-response",
                                    vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_throttle_resp);
    c->vars = c->_vars_stack;
}
