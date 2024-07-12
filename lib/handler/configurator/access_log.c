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

typedef vhttp_VECTOR(vhttp_access_log_filehandle_t *) st_vhttp_access_log_filehandle_vector_t;

struct st_vhttp_access_log_configurator_t {
    vhttp_configurator_t super;
    st_vhttp_access_log_filehandle_vector_t *handles;
    st_vhttp_access_log_filehandle_vector_t _handles_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
};

static int on_config(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_access_log_configurator_t *self = (void *)cmd->configurator;
    yoml_t **path, **format = NULL, **escape_node = NULL;
    int escape = vhttp_LOGCONF_ESCAPE_APACHE;
    vhttp_access_log_filehandle_t *fh;

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        path = &node;
        break;
    case YOML_TYPE_MAPPING:
        if (vhttp_configurator_parse_mapping(cmd, node, "path:s", "format:s,escape:*", &path, &format, &escape_node) != 0)
            return -1;
        break;
    default:
        vhttp_configurator_errprintf(cmd, node, "node must be a scalar or a mapping");
        return -1;
    }

    if (escape_node != NULL) {
        switch (vhttp_configurator_get_one_of(cmd, *escape_node, "apache,json")) {
        case 0:
            escape = vhttp_LOGCONF_ESCAPE_APACHE;
            break;
        case 1:
            escape = vhttp_LOGCONF_ESCAPE_JSON;
            break;
        default:
            return -1;
        }
    }

    if (!ctx->dry_run) {
        if ((fh = vhttp_access_log_open_handle((*path)->data.scalar, format != NULL ? (*format)->data.scalar : NULL, escape)) == NULL)
            return -1;
        vhttp_vector_reserve(NULL, self->handles, self->handles->size + 1);
        self->handles->entries[self->handles->size++] = fh;
    }

    return 0;
}

static int on_config_enter(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_access_log_configurator_t *self = (void *)_self;
    size_t i;

    /* push the stack pointer */
    ++self->handles;

    /* link the handles */
    memset(self->handles, 0, sizeof(*self->handles));
    vhttp_vector_reserve(NULL, self->handles, self->handles[-1].size + 1);
    for (i = 0; i != self->handles[-1].size; ++i) {
        vhttp_access_log_filehandle_t *fh = self->handles[-1].entries[i];
        self->handles[0].entries[self->handles[0].size++] = fh;
        vhttp_mem_addref_shared(fh);
    }

    return 0;
}

static int on_config_exit(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct st_vhttp_access_log_configurator_t *self = (void *)_self;
    size_t i;

    /* register all handles, and decref them */
    for (i = 0; i != self->handles->size; ++i) {
        vhttp_access_log_filehandle_t *fh = self->handles->entries[i];
        if (ctx->pathconf != NULL && !vhttp_configurator_at_extension_level(ctx))
            vhttp_access_log_register(ctx->pathconf, fh);
        vhttp_mem_release_shared(fh);
    }
    /* free the vector */
    free(self->handles->entries);

    /* pop the stack pointer */
    --self->handles;

    return 0;
}

void vhttp_access_log_register_configurator(vhttp_globalconf_t *conf)
{
    struct st_vhttp_access_log_configurator_t *self = (void *)vhttp_configurator_create(conf, sizeof(*self));

    self->super.enter = on_config_enter;
    self->super.exit = on_config_exit;
    self->handles = self->_handles_stack;

    vhttp_configurator_define_command(&self->super, "access-log",
                                    vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH,
                                    on_config);
}
