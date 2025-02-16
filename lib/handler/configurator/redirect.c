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

static int on_config(vhttp_configurator_command_t *cmd, vhttp_configurator_context_t *ctx, yoml_t *node)
{
    const char *dest;
    int status = 302; /* default is temporary redirect */
    int internal = 0; /* default is external redirect */

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        dest = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t **url_node, **status_node, **internal_node;
        if (vhttp_configurator_parse_mapping(cmd, node, "url:s,status:*", "internal:*", &url_node, &status_node, &internal_node) != 0)
            return -1;
        dest = (*url_node)->data.scalar;
        if (vhttp_configurator_scanf(cmd, *status_node, "%d", &status) != 0)
            return -1;
        if (!(300 <= status && status <= 399)) {
            vhttp_configurator_errprintf(cmd, *status_node, "value of property `status` should be within 300 to 399");
            return -1;
        }
        if (internal_node != NULL) {
            switch (vhttp_configurator_get_one_of(cmd, *internal_node, "YES,NO")) {
            case 0:
                internal = 1;
                break;
            case 1:
                internal = 0;
                break;
            default:
                return -1;
            }
        }
    } break;
    default:
        vhttp_configurator_errprintf(cmd, node, "value must be a string or a mapping");
        return -1;
    }

    vhttp_redirect_register(ctx->pathconf, internal, status, dest);

    return 0;
}

void vhttp_redirect_register_configurator(vhttp_globalconf_t *conf)
{
    vhttp_configurator_t *c = vhttp_configurator_create(conf, sizeof(*c));

    vhttp_configurator_define_command(c, "redirect", vhttp_CONFIGURATOR_FLAG_PATH | vhttp_CONFIGURATOR_FLAG_DEFERRED, on_config);
}
