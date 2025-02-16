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
#include "vhttp/configurator.h"

#define DEFAULT_GZIP_QUALITY 1
#define DEFAULT_BROTLI_QUALITY 1

struct compress_configurator_t {
    vhttp_configurator_t super;
    vhttp_compress_args_t *vars, _vars_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static const vhttp_compress_args_t all_off = {0, {-1}, {-1}}, all_on = {100, {DEFAULT_GZIP_QUALITY}, {DEFAULT_BROTLI_QUALITY}};

static int on_config_gzip(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)cmd->configurator;
    int mode;

    if ((mode = (int)vhttp_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;

    *self->vars = all_off;
    if (mode != 0)
        self->vars->gzip.quality = DEFAULT_GZIP_QUALITY;

    return 0;
}

static int obtain_quality(yoml_t *node, int min_quality, int max_quality, int default_quality, int *slot)
{
    int tmp;
    if (node->type != YOML_TYPE_SCALAR)
        return -1;
    if (strcasecmp(node->data.scalar, "OFF") == 0) {
        *slot = -1;
        return 0;
    }
    if (strcasecmp(node->data.scalar, "ON") == 0) {
        *slot = default_quality;
        return 0;
    }
    if (sscanf(node->data.scalar, "%d", &tmp) == 1 && (min_quality <= tmp && tmp <= max_quality)) {
        *slot = tmp;
        return 0;
    }
    return -1;
}

static int on_config_compress_min_size(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)cmd->configurator;
    return vhttp_configurator_scanf(cmd, node, "%zu", &self->vars->min_size);
}

static int on_config_compress(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)cmd->configurator;
    size_t i;

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        if (strcasecmp(node->data.scalar, "OFF") == 0) {
            *self->vars = all_off;
        } else if (strcasecmp(node->data.scalar, "ON") == 0) {
            *self->vars = all_on;
        } else {
            vhttp_configurator_errprintf(cmd, node, "scalar argument must be either of: `OFF`, `ON`");
            return -1;
        }
        break;
    case YOML_TYPE_SEQUENCE:
        *self->vars = all_off;
        for (i = 0; i != node->data.sequence.size; ++i) {
            yoml_t *element = node->data.sequence.elements[i];
            if (element->type == YOML_TYPE_SCALAR && strcasecmp(element->data.scalar, "gzip") == 0) {
                self->vars->gzip.quality = DEFAULT_GZIP_QUALITY;
            } else if (element->type == YOML_TYPE_SCALAR && strcasecmp(element->data.scalar, "br") == 0) {
                self->vars->brotli.quality = DEFAULT_BROTLI_QUALITY;
            } else {
                vhttp_configurator_errprintf(cmd, element, "element of the sequence must be either of: `gzip`, `br`");
                return -1;
            }
        }
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t **gzip_node, **br_node;
        *self->vars = all_off;
        if (vhttp_configurator_parse_mapping(cmd, node, NULL, "gzip:*,br:*", &gzip_node, &br_node) != 0)
            return -1;
        if (gzip_node != NULL && obtain_quality(*gzip_node, 1, 9, DEFAULT_GZIP_QUALITY, &self->vars->gzip.quality) != 0) {
            vhttp_configurator_errprintf(cmd, *gzip_node,
                                       "value of gzip attribute must be either of `OFF`, `ON` or an integer value between 1 and 9");
            return -1;
        }
        if (br_node != NULL && obtain_quality(*br_node, 0, 11, DEFAULT_BROTLI_QUALITY, &self->vars->brotli.quality) != 0) {
            vhttp_configurator_errprintf(cmd, *br_node,
                                       "value of br attribute must be either of `OFF`, `ON` or an integer between 0 and 11");
            return -1;
        }
    } break;
    default:
        vhttp_fatal("unexpected node type");
        break;
    }

    return 0;
}

static int on_config_enter(vhttp_configurator_t *configurator, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)configurator;

    ++self->vars;
    self->vars[0] = self->vars[-1];
    return 0;
}

static int on_config_exit(vhttp_configurator_t *configurator, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct compress_configurator_t *self = (void *)configurator;

    if (ctx->pathconf != NULL && !vhttp_configurator_at_extension_level(ctx) &&
        (self->vars->gzip.quality != -1 || self->vars->brotli.quality != -1))
        vhttp_compress_register(ctx->pathconf, self->vars);

    --self->vars;
    return 0;
}

void vhttp_compress_register_configurator(vhttp_globalconf_t *conf)
{
    struct compress_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;
    vhttp_configurator_define_command(&c->super, "compress",
                                    vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH,
                                    on_config_compress);
    vhttp_configurator_define_command(&c->super, "compress-minimum-size",
                                    vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_compress_min_size);
    vhttp_configurator_define_command(&c->super, "gzip",
                                    vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_gzip);
    c->vars = c->_vars_stack;
    c->vars->gzip.quality = -1;
    c->vars->brotli.quality = -1;
}
