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
#include "vhttp/configurator.h"

static int on_config_status(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    switch (vhttp_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* OFF */
        return 0;
    case 1: /* ON */
        vhttp_status_register(ctx->pathconf);
        return 0;
    default: /* error */
        return -1;
    }
}

struct st_status_configurator {
    vhttp_configurator_t super;
    int stack;
    int duration_stats;
};

static int on_config_duration_stats(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_status_configurator *c = (void *)cmd->configurator;
    ssize_t ret;
    switch (ret = vhttp_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* OFF */
    case 1: /* ON */
        c->duration_stats = (int)ret;
        return 0;
    default: /* error */
        return -1;
    }
}

int on_enter_status(vhttp_configurator_t *_conf, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_status_configurator *c = (void *)_conf;
    c->stack++;
    return 0;
}

int on_exit_status(vhttp_configurator_t *_conf, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_status_configurator *c = (void *)_conf;
    c->stack--;
    if (!c->stack && c->duration_stats) {
        vhttp_duration_stats_register(ctx->globalconf);
    }
    return 0;
}

void vhttp_status_register_configurator(vhttp_globalconf_t *conf)
{
    struct st_status_configurator *c = (void *)vhttp_configurator_create(conf, sizeof(*c));
    c->super.enter = on_enter_status;
    c->super.exit = on_exit_status;

    vhttp_configurator_define_command(
        &c->super, "status", vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_DEFERRED | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_status);

    vhttp_configurator_define_command(&c->super, "duration-stats", vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_duration_stats);
}
