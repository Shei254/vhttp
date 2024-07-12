/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "vhttp.h"
#include "vhttp/configurator.h"
#include "vhttp/mruby_.h"

struct mruby_configurator_t {
    vhttp_configurator_t super;
    vhttp_mruby_config_vars_t *vars;
    vhttp_mruby_config_vars_t _vars_stack[vhttp_CONFIGURATOR_NUM_LEVELS + 1];
    mrb_state *mrb; /* will be lazily initialized */
};

static int compile_test(mrb_state *mrb, vhttp_mruby_config_vars_t *config, char *errbuf)
{
    struct RProc *result = vhttp_mruby_compile_code(mrb, config, errbuf);
    return result != NULL;
}

static mrb_state *get_mrb(struct mruby_configurator_t *self)
{
    if (self->mrb == NULL) {
        self->mrb = mrb_open();
        if (self->mrb == NULL) {
            vhttp_fatal("%s: no memory\n", vhttp_MRUBY_MODULE_NAME);
        }
        vhttp_mruby_setup_globals(self->mrb);
    }
    return self->mrb;
}

static int on_config_mruby_handler(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct mruby_configurator_t *self = (void *)cmd->configurator;

    /* set source */
    self->vars->source = vhttp_strdup(NULL, node->data.scalar, SIZE_MAX);
    self->vars->path = node->filename;
    self->vars->lineno = (int)node->line + 1;

    /* check if there is any error in source */
    char errbuf[1024];
    if (!compile_test(get_mrb(self), self->vars, errbuf)) {
        vhttp_configurator_errprintf(cmd, node, "ruby compile error:%s", errbuf);
        return -1;
    }

    /* register */
    vhttp_mruby_register(ctx->pathconf, self->vars);

    return 0;
}

static int on_config_mruby_handler_file(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct mruby_configurator_t *self = (void *)cmd->configurator;
    FILE *fp = NULL;
    vhttp_iovec_t buf = {NULL};
    int ret = -1;

    /* open and read file */
    if ((fp = fopen(node->data.scalar, "rt")) == NULL) {
        vhttp_configurator_errprintf(cmd, node, "failed to open file: %s:%s", node->data.scalar, strerror(errno));
        goto Exit;
    }
    while (!feof(fp)) {
        buf.base = vhttp_mem_realloc(buf.base, buf.len + 65536);
        buf.len += fread(buf.base + buf.len, 1, 65536, fp);
        if (ferror(fp)) {
            vhttp_configurator_errprintf(cmd, node, "I/O error occurred while reading file:%s:%s", node->data.scalar,
                                       strerror(errno));
            goto Exit;
        }
    }

    /* set source */
    self->vars->source = buf;
    buf.base = NULL;
    self->vars->path = node->data.scalar; /* the value is retained until the end of the configuration phase */
    self->vars->lineno = 0;

    /* check if there is any error in source */
    char errbuf[1024];
    if (!compile_test(get_mrb(self), self->vars, errbuf)) {
        vhttp_configurator_errprintf(cmd, node, "failed to compile file:%s:%s", node->data.scalar, errbuf);
        goto Exit;
    }

    /* register */
    vhttp_mruby_register(ctx->pathconf, self->vars);

    ret = 0;

Exit:
    if (fp != NULL)
        fclose(fp);
    if (buf.base != NULL)
        free(buf.base);
    return ret;
}

static int on_config_mruby_handler_path(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    vhttp_configurator_errprintf(cmd, node, "the command has been removed; see https://github.com/vhttp/vhttp/pull/467");
    return -1;
}

static int on_config_enter(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct mruby_configurator_t *self = (void *)_self;

    memcpy(self->vars + 1, self->vars, sizeof(*self->vars));
    ++self->vars;
    return 0;
}

static int on_config_exit(vhttp_configurator_t *_self, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    struct mruby_configurator_t *self = (void *)_self;

    /* free if the to-be-exitted frame level contains a different source */
    if (self->vars[-1].source.base != self->vars[0].source.base)
        free(self->vars->source.base);

    --self->vars;

    /* release mrb only when global configuration exited */
    if (self->mrb != NULL && ctx->parent == NULL) {
        mrb_close(self->mrb);
        self->mrb = NULL;
    }

    return 0;
}

void vhttp_mruby_register_configurator(vhttp_globalconf_t *conf)
{
    struct mruby_configurator_t *c = (void *)vhttp_configurator_create(conf, sizeof(*c));

    c->vars = c->_vars_stack;
    c->super.enter = on_config_enter;
    c->super.exit = on_config_exit;

    vhttp_configurator_define_command(
        &c->super, "mruby.handler",
        vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_DEFERRED | vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR, on_config_mruby_handler);
    vhttp_configurator_define_command(&c->super, "mruby.handler-file",
                                    vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_DEFERRED |
                                        vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                    on_config_mruby_handler_file);
    vhttp_configurator_define_command(&c->super, "mruby.handler_path", vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_DEFERRED,
                                    on_config_mruby_handler_path);
}
