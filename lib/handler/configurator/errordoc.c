/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd., Kazuho Oku
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

struct errordoc_configurator_t {
    vhttp_configurator_t super;
    vhttp_mem_pool_t pool;
    vhttp_VECTOR(vhttp_errordoc_t) * vars, _vars_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static int register_errordoc(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *hash)
{
    struct errordoc_configurator_t *self = (void *)cmd->configurator;
    yoml_t **url_node, **status_nodes;
    size_t i, j, num_status;

    /* extract the nodes to handle */
    if (vhttp_configurator_parse_mapping(cmd, hash, "url:s,status:*", NULL, &url_node, &status_nodes) != 0)
        return -1;
    switch ((*status_nodes)->type) {
    case YOML_TYPE_SCALAR:
        num_status = 1;
        break;
    case YOML_TYPE_SEQUENCE:
        if ((*status_nodes)->data.sequence.size == 0) {
            vhttp_configurator_errprintf(cmd, *status_nodes, "status cannot be an empty sequence");
            return -1;
        }
        num_status = (*status_nodes)->data.sequence.size;
        status_nodes = (*status_nodes)->data.sequence.elements;
        break;
    default:
        vhttp_configurator_errprintf(cmd, *status_nodes, "status must be a 3-digit scalar or a sequence of 3-digit scalars");
        return -1;
    }

    /* convert list of status_nodes (in string) to list of 3-digit codes */
    int *status_codes = alloca(sizeof(*status_codes) * num_status);
    for (i = 0; i != num_status; ++i) {
        if (vhttp_configurator_scanf(cmd, status_nodes[i], "%d", &status_codes[i]) != 0)
            return -1;
        if (!(400 <= status_codes[i] && status_codes[i] <= 599)) {
            vhttp_configurator_errprintf(cmd, status_nodes[i], "status must be within range of 400 to 599");
            return -1;
        }
        /* check the scanned status hasn't already appeared */
        for (j = 0; j != i; ++j) {
            if (status_codes[j] == status_codes[i]) {
                vhttp_configurator_errprintf(cmd, status_nodes[i], "status %d appears multiple times", status_codes[i]);
                return -1;
            }
        }
    }

    vhttp_iovec_t url = vhttp_strdup(&self->pool, (*url_node)->data.scalar, SIZE_MAX);
    for (i = 0; i != num_status; ++i) {
        /* register */
        vhttp_vector_reserve(&self->pool, self->vars, self->vars->size + 1);
        vhttp_errordoc_t *errordoc = self->vars->entries + self->vars->size++;
        errordoc->status = status_codes[i];
        errordoc->url = url;
    }

    return 0;
}

static int on_config_errordoc(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    switch (node->type) {
    case YOML_TYPE_SEQUENCE: {
        size_t i;
        for (i = 0; i != node->data.sequence.size; ++i) {
            yoml_t *e = node->data.sequence.elements[i];
            if (e->type != YOML_TYPE_MAPPING) {
                vhttp_configurator_errprintf(cmd, e, "element must be a mapping");
                return -1;
            }
            if (register_errordoc(cmd, ctx, e) != 0)
                return -1;
        }
        return 0;
    }
    case YOML_TYPE_MAPPING:
        return register_errordoc(cmd, ctx, node);
    default:
        break;
    }

    vhttp_configurator_errprintf(cmd, node, "argument must be either of: sequence, mapping");
    return -1;
}

static int on_config_enter(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct errordoc_configurator_t *self = (void *)_self;

    if (self->vars == self->_vars_stack) {
        /* entering global level */
        vhttp_mem_init_pool(&self->pool);
    }

    /* copy vars */
    memset(&self->vars[1], 0, sizeof(self->vars[1]));
    vhttp_vector_reserve(&self->pool, &self->vars[1], self->vars[0].size);
    vhttp_memcpy(self->vars[1].entries, self->vars[0].entries, sizeof(self->vars[0].entries[0]) * self->vars[0].size);
    self->vars[1].size = self->vars[0].size;

    ++self->vars;
    return 0;
}

static int on_config_exit(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct errordoc_configurator_t *self = (void *)_self;

    if (ctx->pathconf != NULL && !vhttp_configurator_at_extension_level(ctx) && self->vars->size != 0)
        vhttp_errordoc_register(ctx->pathconf, self->vars->entries, self->vars->size);

    --self->vars;
    if (self->vars == self->_vars_stack) {
        /* exitting global level */
        vhttp_mem_clear_pool(&self->pool);
    }

    return 0;
}

void vhttp_errordoc_register_configurator(vhttp_globalconf_t *conf)
{
    struct errordoc_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    /* set default vars */
    c->vars = c->_vars_stack;

    /* setup handlers */
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    /* reproxy: ON | OFF */
    vhttp_configurator_define_command(&c->super, "error-doc",
                                    vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH,
                                    on_config_errordoc);
}
