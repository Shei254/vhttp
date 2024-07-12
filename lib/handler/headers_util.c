#include "vhttp.h"
#include "vhttp/configurator.h"

static vhttp_header_t *find_header(vhttp_headers_t *headers, vhttp_iovec_t *name)
{
    ssize_t index;

    if (vhttp_iovec_is_token(name)) {
        index = vhttp_find_header(headers, (void *)name, -1);
    } else {
        index = vhttp_find_header_by_str(headers, name->base, name->len, -1);
    }
    if (index == -1)
        return NULL;
    return headers->entries + index;
}

static int is_in_list(const char *base, size_t len, vhttp_headers_command_t *cmd)
{
    size_t i;
    vhttp_iovec_t name = vhttp_iovec_init(base, len);
    for (i = 0; i != cmd->num_args; ++i) {
        if (vhttp_iovec_is_token(cmd->args[i].name)) {
            if (cmd->args[i].name->base == name.base) {
                return 1;
            }
        } else {
            if (vhttp_memis(cmd->args[i].name->base, cmd->args[i].name->len, name.base, name.len))
                return 1;
        }
    }
    return 0;
}

static void filter_cookie(vhttp_mem_pool_t *pool, char **base, size_t *len, vhttp_headers_command_t *cmd)
{
    vhttp_iovec_t iter = vhttp_iovec_init(*base, *len), token_value;
    const char *token;
    size_t token_len;
    char dst[*len * 2];
    size_t dst_len = 0;

    do {
        if ((token = vhttp_next_token(&iter, ';', ';', &token_len, &token_value)) == NULL)
            break;
        int found = is_in_list(token, token_len, cmd);
        if ((cmd->cmd == vhttp_HEADERS_CMD_COOKIE_UNSETUNLESS && found) || (cmd->cmd == vhttp_HEADERS_CMD_COOKIE_UNSET && !found)) {
            if (dst_len != 0) {
                memcpy(dst + dst_len, vhttp_STRLIT("; "));
                dst_len += 2;
            }
            memcpy(dst + dst_len, token, token_len);
            dst_len += token_len;
            if (token_value.len > 0) {
                memcpy(dst + dst_len, vhttp_STRLIT("="));
                dst_len++;
                memcpy(dst + dst_len, token_value.base, token_value.len);
                dst_len += token_value.len;
            }
        }
    } while (1);

    if (dst_len > *len)
        *base = vhttp_mem_alloc_pool(pool, *dst, dst_len);

    memcpy(*base, dst, dst_len);
    *len = dst_len;
}

static void cookie_cmd(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, vhttp_headers_command_t *cmd)
{
    ssize_t header_index;
    for (header_index = -1; (header_index = vhttp_find_header(headers, vhttp_TOKEN_COOKIE, header_index)) != -1;) {
        vhttp_header_t *header = headers->entries + header_index;
        filter_cookie(pool, &header->value.base, &header->value.len, cmd);
        if (header->value.len == 0)
            vhttp_delete_header(headers, header_index);
    }
}

static void remove_header_unless(vhttp_headers_t *headers, vhttp_headers_command_t *cmd)
{
    size_t src, dst = 0;

    for (src = 0; src != headers->size; ++src) {
        if (!is_in_list(headers->entries[src].name->base, headers->entries[src].name->len, cmd))
            continue;
        /* not matched */
        if (dst != src)
            headers->entries[dst] = headers->entries[src];
        ++dst;
    }
    headers->size = dst;
}

static void remove_header(vhttp_headers_t *headers, vhttp_headers_command_t *cmd)
{
    size_t src, dst = 0;

    for (src = 0; src != headers->size; ++src) {
        if (vhttp_iovec_is_token(cmd->args[0].name)) {
            if (headers->entries[src].name == cmd->args[0].name)
                continue;
        } else {
            if (vhttp_memis(headers->entries[src].name->base, headers->entries[src].name->len, cmd->args[0].name->base,
                          cmd->args[0].name->len))
                continue;
        }
        /* not matched */
        if (dst != src)
            headers->entries[dst] = headers->entries[src];
        ++dst;
    }
    headers->size = dst;
}

static void dispose_vhttp_headers_command(void *_cmds)
{
    vhttp_headers_command_t *cmds = _cmds;
    size_t i;
    for (i = 0; cmds[i].cmd != vhttp_HEADERS_CMD_NULL; ++i)
        free(cmds[i].args);
}

void vhttp_headers_append_command(vhttp_headers_command_t **cmds, int cmd, vhttp_headers_command_arg_t *args, size_t num_args,
                                vhttp_headers_command_when_t when)
{
    vhttp_headers_command_t *new_cmds;
    size_t i, cnt;

    if (*cmds != NULL) {
        for (cnt = 0; (*cmds)[cnt].cmd != vhttp_HEADERS_CMD_NULL; ++cnt)
            ;
    } else {
        cnt = 0;
    }

    new_cmds = vhttp_mem_alloc_shared(NULL, (cnt + 2) * sizeof(*new_cmds), dispose_vhttp_headers_command);
    if (*cmds != NULL)
        memcpy(new_cmds, *cmds, cnt * sizeof(*new_cmds));
    new_cmds[cnt] = (vhttp_headers_command_t){};
    new_cmds[cnt].cmd = cmd;
    new_cmds[cnt].when = when;
    new_cmds[cnt].args = vhttp_mem_alloc(sizeof(*new_cmds->args) * num_args);
    for (i = 0; i < num_args; i++)
        new_cmds[cnt].args[i] = args[i];
    new_cmds[cnt].num_args = num_args;
    new_cmds[cnt + 1] = (vhttp_headers_command_t){vhttp_HEADERS_CMD_NULL};

    if (*cmds != NULL) {
        (*cmds)[0] = (vhttp_headers_command_t){vhttp_HEADERS_CMD_NULL};
        vhttp_mem_release_shared(*cmds);
    }
    *cmds = new_cmds;
}

void vhttp_rewrite_headers(vhttp_mem_pool_t *pool, vhttp_headers_t *headers, vhttp_headers_command_t *cmd)
{
    vhttp_header_t *target;

    switch (cmd->cmd) {
    case vhttp_HEADERS_CMD_ADD:
        goto AddHeader;
    case vhttp_HEADERS_CMD_APPEND:
        assert(cmd->num_args == 1);
        if ((target = find_header(headers, cmd->args[0].name)) == NULL)
            goto AddHeader;
        goto AppendToken;
    case vhttp_HEADERS_CMD_MERGE:
        assert(cmd->num_args == 1);
        if ((target = find_header(headers, cmd->args[0].name)) == NULL)
            goto AddHeader;
        if (vhttp_contains_token(target->value.base, target->value.len, cmd->args[0].value.base, cmd->args[0].value.len, ','))
            return;
        goto AppendToken;
    case vhttp_HEADERS_CMD_SET:
        remove_header(headers, cmd);
        goto AddHeader;
    case vhttp_HEADERS_CMD_SETIFEMPTY:
        assert(cmd->num_args == 1);
        if (find_header(headers, cmd->args[0].name) != NULL)
            return;
        goto AddHeader;
    case vhttp_HEADERS_CMD_UNSET:
        remove_header(headers, cmd);
        return;
    case vhttp_HEADERS_CMD_UNSETUNLESS:
        remove_header_unless(headers, cmd);
        return;
    case vhttp_HEADERS_CMD_COOKIE_UNSET:
    case vhttp_HEADERS_CMD_COOKIE_UNSETUNLESS:
        cookie_cmd(pool, headers, cmd);
        return;
    }

    assert(!"FIXME");
    return;

AddHeader:
    assert(cmd->num_args == 1);
    if (vhttp_iovec_is_token(cmd->args[0].name)) {
        vhttp_add_header(pool, headers, (void *)cmd->args[0].name, NULL, cmd->args[0].value.base, cmd->args[0].value.len);
    } else {
        vhttp_add_header_by_str(pool, headers, cmd->args[0].name->base, cmd->args[0].name->len, 0, NULL, cmd->args[0].value.base,
                              cmd->args[0].value.len);
    }
    return;

AppendToken:
    assert(cmd->num_args == 1);
    if (target->value.len != 0) {
        vhttp_iovec_t v;
        v.len = target->value.len + 2 + cmd->args[0].value.len;
        v.base = vhttp_mem_alloc_pool(pool, char, v.len);
        memcpy(v.base, target->value.base, target->value.len);
        v.base[target->value.len] = ',';
        v.base[target->value.len + 1] = ' ';
        memcpy(v.base + target->value.len + 2, cmd->args[0].value.base, cmd->args[0].value.len);
        target->value = v;
    } else {
        target->value = cmd->args[0].value;
    }
    return;
}
