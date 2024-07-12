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
#ifndef vhttp__configurator_h
#define vhttp__configurator_h

#include "yoml.h"

enum {
    vhttp_CONFIGURATOR_FLAG_GLOBAL = 0x1,
    vhttp_CONFIGURATOR_FLAG_HOST = 0x2,
    vhttp_CONFIGURATOR_FLAG_PATH = 0x4,
    vhttp_CONFIGURATOR_FLAG_EXTENSION = 0x8,
    vhttp_CONFIGURATOR_FLAG_ALL_LEVELS =
        vhttp_CONFIGURATOR_FLAG_GLOBAL | vhttp_CONFIGURATOR_FLAG_HOST | vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_EXTENSION,
    vhttp_CONFIGURATOR_FLAG_EXPECT_SCALAR = 0x100,
    vhttp_CONFIGURATOR_FLAG_EXPECT_SEQUENCE = 0x200,
    vhttp_CONFIGURATOR_FLAG_EXPECT_MAPPING = 0x400,
    vhttp_CONFIGURATOR_FLAG_DEFERRED = 0x1000,
    vhttp_CONFIGURATOR_FLAG_SEMI_DEFERRED =
        0x2000 /* used by listen, file.custom-handler (invoked before hosts,paths,file-dir, etc.) */
};

#define vhttp_CONFIGURATOR_NUM_LEVELS 4

typedef struct st_vhttp_configurator_context_t {
    /**
     * pointer to globalconf
     */
    vhttp_globalconf_t *globalconf;
    /**
     * pointer to hostconf, or NULL if the context is above host level
     */
    vhttp_hostconf_t *hostconf;
    /**
     * pointer to pathconf (either at path level or custom handler level), or NULL
     */
    vhttp_pathconf_t *pathconf;
    /**
     * pointer to mimemap
     */
    vhttp_mimemap_t **mimemap;
    /**
     * pointer to env
     */
    vhttp_envconf_t *env;
    /**
     * if is a dry run
     */
    int dry_run;
    /**
     * parent context (or NULL if the context is at global level)
     */
    struct st_vhttp_configurator_context_t *parent;
} vhttp_configurator_context_t;

typedef int (*vhttp_configurator_dispose_cb)(vhttp_configurator_t *configurator);
typedef int (*vhttp_configurator_enter_cb)(vhttp_configurator_t *configurator, vhttp_configurator_context_t *ctx, yoml_t *node);
typedef int (*vhttp_configurator_exit_cb)(vhttp_configurator_t *configurator, vhttp_configurator_context_t *ctx, yoml_t *node);
typedef int (*vhttp_configurator_command_cb)(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node);
typedef vhttp_headers_command_t **(*vhttp_configurator_get_headers_commands_cb)(vhttp_configurator_t *conf);

struct st_vhttp_configurator_command_t {
    /**
     * configurator to which the command belongs
     */
    vhttp_configurator_t *configurator;
    /**
     * name of the command handled by the configurator
     */
    const char *name;
    /**
     * flags
     */
    int flags;
    /**
     * mandatory callback called to handle the command
     */
    vhttp_configurator_command_cb cb;
};

/**
 * basic structure of a configurator (handles a configuration command)
 */
struct st_vhttp_configurator_t {
    vhttp_linklist_t _link;
    /**
     * optional callback called when the global config is being disposed
     */
    vhttp_configurator_dispose_cb dispose;
    /**
     * optional callback called before the configuration commands are handled
     */
    vhttp_configurator_enter_cb enter;
    /**
     * optional callback called after all the configuration commands are handled
     */
    vhttp_configurator_exit_cb exit;
    /**
     * list of commands
     */
    vhttp_VECTOR(vhttp_configurator_command_t) commands;
};

/**
 * registers a configurator
 */
vhttp_configurator_t *vhttp_configurator_create(vhttp_globalconf_t *conf, size_t sz);
/**
 *
 */
void vhttp_configurator_define_command(vhttp_configurator_t *configurator, const char *name, int flags, vhttp_configurator_command_cb cb);
/**
 * returns a configurator of given command name
 * @return configurator for given name or NULL if not found
 */
vhttp_configurator_command_t *vhttp_configurator_get_command(vhttp_globalconf_t *conf, const char *name);
/**
 * applies the configuration to the context
 * @return 0 if successful, -1 if not
 */
int vhttp_configurator_apply(vhttp_globalconf_t *config, yoml_t *node, int dry_run);
/**
 *
 */
int vhttp_configurator_apply_commands(vhttp_configurator_context_t *ctx, yoml_t *node, int flags_mask, const char **ignore_commands);
/**
 *
 */
static int vhttp_configurator_at_extension_level(vhttp_configurator_context_t *ctx);
/**
 * emits configuration error
 */
void vhttp_configurator_errprintf(vhttp_configurator_command_t *cmd, yoml_t *node, const char *reason, ...)
    __attribute__((format(printf, 3, 4)));
/**
 * interprets the configuration value using sscanf, or prints an error upon failure
 * @param configurator configurator
 * @param node configuration value
 * @param fmt scanf-style format string
 * @return 0 if successful, -1 if not
 */
int vhttp_configurator_scanf(vhttp_configurator_command_t *cmd, yoml_t *node, const char *fmt, ...)
    __attribute__((format(scanf, 3, 4)));
/**
 * interprets the configuration value and returns the index of the matched string within the candidate strings, or prints an error
 * upon failure
 * @param configurator configurator
 * @param node configuration value
 * @param candidates a comma-separated list of strings (should not contain whitespaces)
 * @return index of the matched string within the given list, or -1 if none of them matched
 */
ssize_t vhttp_configurator_get_one_of(vhttp_configurator_command_t *cmd, yoml_t *node, const char *candidates);
/**
 * extracts values (required and optional) from a mapping by their keys, or prints an error upon failure
 * @param configurator configurator
 * @param node the mapping to parse
 * @param keys_required comma-separated list of required keys (or NULL)
 * @param keys_optional comma-separated list of optional keys (or NULL)
 * @param ... pointers to `yoml_t **` for receiving the results; they should appear in the order they appear in the key names
 * @return 0 if successful, -1 if not
 */
#define vhttp_configurator_parse_mapping(cmd, node, keys_required, keys_optional, ...)                                               \
    vhttp_configurator__do_parse_mapping((cmd), (node), (keys_required), (keys_optional), (yoml_t * **[]){__VA_ARGS__},              \
                                       sizeof((yoml_t ***[]){__VA_ARGS__}) / sizeof(yoml_t ***))
int vhttp_configurator__do_parse_mapping(vhttp_configurator_command_t *cmd, yoml_t *node, const char *keys_required,
                                       const char *keys_optional, yoml_t ****values, size_t num_values);
/**
 * returns the absolute paths of supplementary commands
 */
char *vhttp_configurator_get_cmd_path(const char *cmd);

/**
 * lib/handler/configurator/headers_util.c
 */
void vhttp_configurator_define_headers_commands(vhttp_globalconf_t *global_conf, vhttp_configurator_t *conf, const char *prefix,
                                              vhttp_configurator_get_headers_commands_cb get_commands);

void vhttp_configurator__init_core(vhttp_globalconf_t *conf);
void vhttp_configurator__dispose_configurators(vhttp_globalconf_t *conf);

/* inline definitions */

inline int vhttp_configurator_at_extension_level(vhttp_configurator_context_t *ctx)
{
    return ctx->pathconf != NULL && ctx->pathconf->path.base == NULL && ctx->pathconf != &ctx->hostconf->fallback_path;
}

#endif
