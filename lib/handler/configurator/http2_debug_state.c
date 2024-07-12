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
#include "vhttp.h"
#include "vhttp/configurator.h"

static int on_config_debug_state(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    switch (vhttp_configurator_get_one_of(cmd, node, "minimum,hpack")) {
    case 0: /* minimum */
        vhttp_http2_debug_state_register(ctx->hostconf, 0);
        return 0;
    case 1: /* with hpack state*/
        vhttp_http2_debug_state_register(ctx->hostconf, 1);
        return 0;
    default: /* error */
        return -1;
    }
}

void vhttp_http2_debug_state_register_configurator(vhttp_globalconf_t *conf)
{
    struct st_vhttp_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    vhttp_configurator_define_command(
        c, "http2-debug-state", vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_DEFERRED | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_debug_state);
}
