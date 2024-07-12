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
#include "vhttp.h"
#include "vhttp/configurator.h"

struct st_vhttp_file_config_vars_t {
    const char **index_files;
    int flags;
};

struct st_vhttp_file_configurator_t {
    vhttp_configurator_t super;
    struct st_vhttp_file_config_vars_t *vars;
    struct st_vhttp_file_config_vars_t _vars_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config_dir(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_file_configurator_t *self = (void *)cmd->configurator;

    vhttp_file_register(ctx->pathconf, node->data.scalar, self->vars->index_files, *ctx->mimemap, self->vars->flags);
    return 0;
}

static int on_config_file(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_file_configurator_t *self = (void *)cmd->configurator;
    vhttp_mimemap_type_t *mime_type =
        vhttp_mimemap_get_type_by_extension(*ctx->mimemap, vhttp_get_filext(node->data.scalar, strlen(node->data.scalar)));
    vhttp_file_register_file(ctx->pathconf, node->data.scalar, mime_type, self->vars->flags);
    return 0;
}

static int on_config_index(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_file_configurator_t *self = (void *)cmd->configurator;
    size_t i;

    free(self->vars->index_files);
    self->vars->index_files = vhttp_mem_alloc(sizeof(self->vars->index_files[0]) * (node->data.sequence.size + 1));
    for (i = 0; i != node->data.sequence.size; ++i) {
        yoml_t *element = node->data.sequence.elements[i];
        if (element->type != YOML_TYPE_SCALAR) {
            vhttp_configurator_errprintf(cmd, element, "argument must be a sequence of scalars");
            return -1;
        }
        self->vars->index_files[i] = element->data.scalar;
    }
    self->vars->index_files[i] = NULL;

    return 0;
}

static int on_config_etag(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_file_configurator_t *self = (void *)cmd->configurator;

    switch (vhttp_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* off */
        self->vars->flags |= vhttp_FILE_FLAG_NO_ETAG;
        break;
    case 1: /* on */
        self->vars->flags &= ~vhttp_FILE_FLAG_NO_ETAG;
        break;
    default: /* error */
        return -1;
    }

    return 0;
}

static int on_config_send_compressed(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_file_configurator_t *self = (void *)cmd->configurator;

    switch (vhttp_configurator_get_one_of(cmd, node, "OFF,ON,gunzip")) {
    case 0: /* off */
        self->vars->flags &= ~vhttp_FILE_FLAG_SEND_COMPRESSED;
        break;
    case 1: /* on */
        self->vars->flags |= vhttp_FILE_FLAG_SEND_COMPRESSED;
        break;
    case 2: /* gunzip */
        self->vars->flags |= (vhttp_FILE_FLAG_SEND_COMPRESSED | vhttp_FILE_FLAG_GUNZIP);
        break;
    default: /* error */
        return -1;
    }

    return 0;
}

static int on_config_dir_listing(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_file_configurator_t *self = (void *)cmd->configurator;

    switch (vhttp_configurator_get_one_of(cmd, node, "OFF,ON")) {
    case 0: /* off */
        self->vars->flags &= ~vhttp_FILE_FLAG_DIR_LISTING;
        break;
    case 1: /* on */
        self->vars->flags |= vhttp_FILE_FLAG_DIR_LISTING;
        break;
    default: /* error */
        return -1;
    }

    return 0;
}

static const char **dup_strlist(const char **s)
{
    size_t i;
    const char **ret;

    for (i = 0; s[i] != NULL; ++i)
        ;
    ret = vhttp_mem_alloc(sizeof(*ret) * (i + 1));
    for (i = 0; s[i] != NULL; ++i)
        ret[i] = s[i];
    ret[i] = NULL;

    return ret;
}

static int on_config_enter(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_file_configurator_t *self = (void *)_self;
    ++self->vars;
    self->vars[0].index_files = dup_strlist(self->vars[-1].index_files);
    self->vars[0].flags = self->vars[-1].flags;
    return 0;
}

static int on_config_exit(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_file_configurator_t *self = (void *)_self;
    free(self->vars->index_files);
    --self->vars;
    return 0;
}

void vhttp_file_register_configurator(vhttp_globalconf_t *globalconf)
{
    struct st_vhttp_file_configurator_t *self = (void *)vhttp_configurator_create(globalconf, sizeof(*self));

    self->super.enter = on_config_enter;
    self->super.exit = on_config_exit;
    self->vars = self->_vars_stack;
    self->vars->index_files = vhttp_file_default_index_files;

    vhttp_configurator_define_command(
        &self->super, "file.dir", vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR | vhttp_CONFIGURATOR_FLAG_DEFERRED,
        on_config_dir);
    vhttp_configurator_define_command(
        &self->super, "file.file",
        vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR | vhttp_CONFIGURATOR_FLAG_DEFERRED, on_config_file);
    vhttp_configurator_define_command(&self->super, "file.index",
                                    (vhttp_CONFIGURATOR_FLAG_ALL_LEVELS & ~vhttp_CONFIGURATOR_FLAG_EXTENSION) |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SEQUENCE,
                                    on_config_index);
    vhttp_configurator_define_command(&self->super, "file.etag",
                                    (vhttp_CONFIGURATOR_FLAG_ALL_LEVELS & ~vhttp_CONFIGURATOR_FLAG_EXTENSION) |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_etag);
    vhttp_configurator_define_command(&self->super, "file.send-compressed",
                                    (vhttp_CONFIGURATOR_FLAG_ALL_LEVELS & ~vhttp_CONFIGURATOR_FLAG_EXTENSION) |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_send_compressed);
    vhttp_configurator_define_command(&self->super, "file.send-gzip",
                                    (vhttp_CONFIGURATOR_FLAG_ALL_LEVELS & ~vhttp_CONFIGURATOR_FLAG_EXTENSION) |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_send_compressed);
    vhttp_configurator_define_command(&self->super, "file.dirlisting",
                                    (vhttp_CONFIGURATOR_FLAG_ALL_LEVELS & ~vhttp_CONFIGURATOR_FLAG_EXTENSION) |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_dir_listing);
}
