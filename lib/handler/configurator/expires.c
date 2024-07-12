/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <stdio.h>
#include <string.h>
#include "vhttp.h"
#include "vhttp/configurator.h"

struct expires_configurator_t {
    vhttp_configurator_t super;
    vhttp_expires_args_t **args;
    vhttp_expires_args_t *_args_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_expires(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct expires_configurator_t *self = (void *)cmd->configurator;
    uint64_t value;
    char unit[32];

    if (strcasecmp(node->data.scalar, "OFF") == 0) {
        free(*self->args);
        *self->args = NULL;
    } else if (sscanf(node->data.scalar, "%" SCNu64 " %31s", &value, unit) == 2) {
        /* convert value to seconds depending on the unit */
        if (strncasecmp(unit, vhttp_STRLIT("second")) == 0) {
            /* ok */
        } else if (strncasecmp(unit, vhttp_STRLIT("minute")) == 0) {
            value *= 60;
        } else if (strncasecmp(unit, vhttp_STRLIT("hour")) == 0) {
            value *= 60 * 60;
        } else if (strncasecmp(unit, vhttp_STRLIT("day")) == 0) {
            value *= 24 * 60 * 60;
        } else if (strncasecmp(unit, vhttp_STRLIT("month")) == 0) {
            value *= 30 * 24 * 60 * 60;
        } else if (strncasecmp(unit, vhttp_STRLIT("year")) == 0) {
            value *= 365 * 30 * 24 * 60 * 60;
        } else {
            /* TODO add support for vhttp_EXPIRES_MODE_MAX_ABSOLUTE that sets the Expires header? */
            vhttp_configurator_errprintf(cmd, node, "unknown unit:`%s` (see --help)", unit);
            return -1;
        }
        /* save the value */
        if (*self->args == NULL)
            *self->args = vhttp_mem_alloc(sizeof(**self->args));
        (*self->args)->mode = vhttp_EXPIRES_MODE_MAX_AGE;
        (*self->args)->data.max_age = value;
    } else {
        vhttp_configurator_errprintf(cmd, node,
                                   "failed to parse the value, should be in form of: `<number> <unit>` or `OFF` (see --help)");
        return -1;
    }

    return 0;
}

static int on_config_enter(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct expires_configurator_t *self = (void *)_self;

    if (self->args[0] != NULL) {
        /* duplicate */
        assert(self->args[0]->mode == vhttp_EXPIRES_MODE_MAX_AGE);
        self->args[1] = vhttp_mem_alloc(sizeof(**self->args));
        *self->args[1] = *self->args[0];
    } else {
        self->args[1] = NULL;
    }
    ++self->args;
    return 0;
}

static int on_config_exit(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct expires_configurator_t *self = (void *)_self;

    if (*self->args != NULL) {
        /* setup */
        if (ctx->pathconf != NULL && !vhttp_configurator_at_extension_level(ctx))
            vhttp_expires_register(ctx->pathconf, *self->args);
        /* destruct */
        assert((*self->args)->mode == vhttp_EXPIRES_MODE_MAX_AGE);
        free(*self->args);
        *self->args = NULL;
    }

    --self->args;
    return 0;
}

void vhttp_expires_register_configurator(vhttp_globalconf_t *conf)
{
    struct expires_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->args = c->_args_stack;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    vhttp_configurator_define_command(&c->super, "expires",
                                    vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_expires);
}
