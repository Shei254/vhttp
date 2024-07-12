/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd.
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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "vhttp/memory.h"
#include "vhttp/string_.h"
#include "vhttp/url.h"

const vhttp_url_scheme_t vhttp_URL_SCHEME_HTTP = {{vhttp_STRLIT("http")}, 80, 0};
const vhttp_url_scheme_t vhttp_URL_SCHEME_HTTPS = {{vhttp_STRLIT("https")}, 443, 1};
const vhttp_url_scheme_t vhttp_URL_SCHEME_MASQUE = {{vhttp_STRLIT("masque")}, 65535, 0 /* ??? masque might or might not be over TLS */};
const vhttp_url_scheme_t vhttp_URL_SCHEME_FASTCGI = {{vhttp_STRLIT("fastcgi")}, 65535, 0};

static int decode_hex(int ch)
{
    if ('0' <= ch && ch <= '9')
        return ch - '0';
    if ('A' <= ch && ch <= 'F')
        return ch - 'A' + 0xa;
    if ('a' <= ch && ch <= 'f')
        return ch - 'a' + 0xa;
    return -1;
}

static size_t handle_special_paths(const char *path, size_t off, size_t last_slash)
{
    size_t orig_off = off, part_size = off - last_slash;

    if (part_size == 2 && path[off - 1] == '.') {
        --off;
    } else if (part_size == 3 && path[off - 2] == '.' && path[off - 1] == '.') {
        off -= 2;
        if (off > 1) {
            for (--off; path[off - 1] != '/'; --off)
                ;
        }
    }
    return orig_off - off;
}

/* Perform path normalization and URL decoding in one pass.
 * See vhttp_req_t for the purpose of @norm_indexes. */
static vhttp_iovec_t rebuild_path(vhttp_mem_pool_t *pool, const char *src, size_t src_len, size_t *query_at, size_t **norm_indexes)
{
    char *dst;
    size_t src_off = 0, dst_off = 0, last_slash, rewind;

    { /* locate '?', and set len to the end of input path */
        const char *q = memchr(src, '?', src_len);
        if (q != NULL) {
            src_len = *query_at = q - src;
        } else {
            *query_at = SIZE_MAX;
        }
    }

    /* dst can be 1 byte more than src if src is missing the prefixing '/' */
    dst = vhttp_mem_alloc_pool(pool, char, src_len + 1);
    *norm_indexes = vhttp_mem_alloc_pool(pool, *norm_indexes[0], (src_len + 1));

    if (src[0] == '/')
        src_off++;
    last_slash = dst_off;
    dst[dst_off] = '/';
    (*norm_indexes)[dst_off] = src_off;
    dst_off++;

    /* decode %xx */
    while (src_off < src_len) {
        int hi, lo;
        char decoded;

        if (src[src_off] == '%' && (src_off + 2 < src_len) && (hi = decode_hex(src[src_off + 1])) != -1 &&
            (lo = decode_hex(src[src_off + 2])) != -1) {
            decoded = (hi << 4) | lo;
            src_off += 3;
        } else {
            decoded = src[src_off++];
        }
        if (decoded == '/') {
            rewind = handle_special_paths(dst, dst_off, last_slash);
            if (rewind > 0) {
                dst_off -= rewind;
                last_slash = dst_off - 1;
                continue;
            }
            last_slash = dst_off;
        }
        dst[dst_off] = decoded;
        (*norm_indexes)[dst_off] = src_off;
        dst_off++;
    }
    rewind = handle_special_paths(dst, dst_off, last_slash);
    dst_off -= rewind;

    return vhttp_iovec_init(dst, dst_off);
}

vhttp_iovec_t vhttp_url_normalize_path(vhttp_mem_pool_t *pool, const char *path, size_t len, size_t *query_at, size_t **norm_indexes)
{
    vhttp_iovec_t ret;

    *query_at = SIZE_MAX;
    *norm_indexes = NULL;

    if (len == 0) {
        ret = vhttp_iovec_init("/", 1);
        return ret;
    }

    const char *p = path, *end = path + len;

    if (path[0] != '/')
        goto Rewrite;

    for (; p + 1 < end; ++p) {
        if ((p[0] == '/' && p[1] == '.') || p[0] == '%') {
            /* detect false positives as well */
            goto Rewrite;
        } else if (p[0] == '?') {
            *query_at = p - path;
            goto Return;
        }
    }
    for (; p < end; ++p) {
        if (p[0] == '?') {
            *query_at = p - path;
            goto Return;
        }
    }

Return:
    ret.base = (char *)path;
    ret.len = p - path;
    return ret;

Rewrite:
    ret = rebuild_path(pool, path, len, query_at, norm_indexes);
    if (ret.len == 0)
        goto RewriteError;
    if (ret.base[0] != '/')
        goto RewriteError;
    if (vhttp_strstr(ret.base, ret.len, vhttp_STRLIT("/../")) != SIZE_MAX)
        goto RewriteError;
    if (ret.len >= 3 && memcmp(ret.base + ret.len - 3, "/..", 3) == 0)
        goto RewriteError;
    return ret;
RewriteError:
    vhttp_error_printf("failed to normalize path: `%.*s` => `%.*s`\n", (int)len, path, (int)ret.len, ret.base);
    ret = vhttp_iovec_init("/", 1);
    return ret;
}

static const char *parse_scheme(const char *s, const char *end, const vhttp_url_scheme_t **scheme)
{
    if (end - s >= 5 && memcmp(s, "http:", 5) == 0) {
        *scheme = &vhttp_URL_SCHEME_HTTP;
        return s + 5;
    } else if (end - s >= 6 && memcmp(s, "https:", 6) == 0) {
        *scheme = &vhttp_URL_SCHEME_HTTPS;
        return s + 6;
    } else if (end - s >= 7 && memcmp(s, "masque:", 7) == 0) {
        *scheme = &vhttp_URL_SCHEME_MASQUE;
        return s + 7;
    }
    return NULL;
}

const char *vhttp_url_parse_hostport(const char *s, size_t len, vhttp_iovec_t *host, uint16_t *port)
{
    const char *token_start = s, *token_end, *end = s + len;

    *port = 65535;

    if (token_start == end)
        return NULL;

    if (*token_start == '[') {
        /* is IPv6 address */
        ++token_start;
        if ((token_end = memchr(token_start, ']', end - token_start)) == NULL)
            return NULL;
        *host = vhttp_iovec_init(token_start, token_end - token_start);
        token_start = token_end + 1;
    } else {
        for (token_end = token_start; !(token_end == end || *token_end == '/' || *token_end == '?' || *token_end == ':');
             ++token_end)
            ;
        *host = vhttp_iovec_init(token_start, token_end - token_start);
        token_start = token_end;
    }

    /* disallow zero-length host */
    if (host->len == 0)
        return NULL;

    /* parse port */
    if (token_start != end && *token_start == ':') {
        uint32_t p = 0;
        for (++token_start; token_start != end; ++token_start) {
            if ('0' <= *token_start && *token_start <= '9') {
                p = p * 10 + *token_start - '0';
                if (p >= 65535)
                    return NULL;
            } else if (*token_start == '/' || *token_start == '?') {
                break;
            }
        }
        *port = (uint16_t)p;
    }

    return token_start;
}

static int parse_authority_and_path(vhttp_mem_pool_t *pool, const char *src, const char *url_end, vhttp_url_t *parsed)
{
    const char *p = vhttp_url_parse_hostport(src, url_end - src, &parsed->host, &parsed->_port);
    if (p == NULL)
        return -1;
    parsed->authority = vhttp_iovec_init(src, p - src);
    if (p == url_end) {
        parsed->path = vhttp_iovec_init(vhttp_STRLIT("/"));
    } else if (*p == '/') {
        parsed->path = vhttp_iovec_init(p, url_end - p);
    } else if (*p == '?') {
        parsed->path = vhttp_concat(pool, vhttp_iovec_init(vhttp_STRLIT("/")), vhttp_iovec_init(p, url_end - p));
    } else {
        return -1;
    }
    return 0;
}

int vhttp_url_parse(vhttp_mem_pool_t *pool, const char *url, size_t url_len, vhttp_url_t *parsed)
{
    const char *url_end, *p;

    if (url_len == SIZE_MAX)
        url_len = strlen(url);
    url_end = url + url_len;

    /* check and skip scheme */
    if ((p = parse_scheme(url, url_end, &parsed->scheme)) == NULL)
        return -1;

    /* skip "//" */
    if (!(url_end - p >= 2 && p[0] == '/' && p[1] == '/'))
        return -1;
    p += 2;

    return parse_authority_and_path(pool, p, url_end, parsed);
}

int vhttp_url_parse_relative(vhttp_mem_pool_t *pool, const char *url, size_t url_len, vhttp_url_t *parsed)
{
    const char *url_end, *p;

    if (url_len == SIZE_MAX)
        url_len = strlen(url);
    url_end = url + url_len;

    /* obtain scheme and port number */
    if ((p = parse_scheme(url, url_end, &parsed->scheme)) == NULL) {
        parsed->scheme = NULL;
        p = url;
    }

    /* handle "//" */
    if (url_end - p >= 2 && p[0] == '/' && p[1] == '/')
        return parse_authority_and_path(pool, p + 2, url_end, parsed);

    /* reset authority, host, port, and set path */
    parsed->authority = (vhttp_iovec_t){NULL};
    parsed->host = (vhttp_iovec_t){NULL};
    parsed->_port = 65535;
    parsed->path = vhttp_iovec_init(p, url_end - p);

    return 0;
}

vhttp_iovec_t vhttp_url_resolve(vhttp_mem_pool_t *pool, const vhttp_url_t *base, const vhttp_url_t *relative, vhttp_url_t *dest)
{
    vhttp_iovec_t base_path, relative_path, ret;

    assert(base->path.len != 0);
    assert(base->path.base[0] == '/');

    if (relative == NULL) {
        /* build URL using base copied to dest */
        *dest = *base;
        base_path = base->path;
        relative_path = vhttp_iovec_init(NULL, 0);
        goto Build;
    }

    /* scheme */
    dest->scheme = relative->scheme != NULL ? relative->scheme : base->scheme;

    /* authority (and host:port) */
    if (relative->authority.base != NULL) {
        assert(relative->host.base != NULL);
        dest->authority = relative->authority;
        dest->host = relative->host;
        dest->_port = relative->_port;
    } else {
        assert(relative->host.base == NULL);
        assert(relative->_port == 65535);
        dest->authority = base->authority;
        dest->host = base->host;
        dest->_port = base->_port;
    }

    /* path */
    base_path = base->path;
    if (relative->path.base != NULL) {
        relative_path = relative->path;
        vhttp_url_resolve_path(&base_path, &relative_path);
    } else {
        assert(relative->path.len == 0);
        relative_path = (vhttp_iovec_t){NULL};
    }

Build:
    /* build the output */
    ret = vhttp_concat(pool, dest->scheme->name, vhttp_iovec_init(vhttp_STRLIT("://")), dest->authority, base_path, relative_path);
    /* adjust dest */
    dest->authority.base = ret.base + dest->scheme->name.len + 3;
    dest->host.base = dest->authority.base;
    if (dest->authority.len != 0 && dest->authority.base[0] == '[')
        ++dest->host.base;
    dest->path.base = dest->authority.base + dest->authority.len;
    dest->path.len = ret.base + ret.len - dest->path.base;

    return ret;
}

void vhttp_url_resolve_path(vhttp_iovec_t *base, vhttp_iovec_t *relative)
{
    size_t base_path_len = base->len, rel_path_offset = 0;

    if (relative->len != 0 && relative->base[0] == '/') {
        base_path_len = 0;
    } else {
        /* relative path */
        while (base->base[--base_path_len] != '/')
            ;
        while (rel_path_offset != relative->len) {
            if (relative->base[rel_path_offset] == '.') {
                if (relative->len - rel_path_offset >= 2 && relative->base[rel_path_offset + 1] == '.' &&
                    (relative->len - rel_path_offset == 2 || relative->base[rel_path_offset + 2] == '/')) {
                    if (base_path_len != 0) {
                        while (base->base[--base_path_len] != '/')
                            ;
                    }
                    rel_path_offset += relative->len - rel_path_offset == 2 ? 2 : 3;
                    continue;
                }
                if (relative->len - rel_path_offset == 1) {
                    rel_path_offset += 1;
                    continue;
                } else if (relative->base[rel_path_offset + 1] == '/') {
                    rel_path_offset += 2;
                    continue;
                }
            }
            break;
        }
        base_path_len += 1;
    }

    base->len = base_path_len;
    *relative = vhttp_iovec_init(relative->base + rel_path_offset, relative->len - rel_path_offset);
}

void vhttp_url_copy(vhttp_mem_pool_t *pool, vhttp_url_t *dest, const vhttp_url_t *src)
{
    dest->scheme = src->scheme;
    dest->authority = vhttp_strdup(pool, src->authority.base, src->authority.len);
    dest->host = vhttp_strdup(pool, src->host.base, src->host.len);
    dest->path = vhttp_strdup(pool, src->path.base, src->path.len);
    dest->_port = src->_port;
}

const char *vhttp_url_host_to_sun(vhttp_iovec_t host, struct sockaddr_un *sa)
{
#define PREFIX "unix:"

    if (host.len < sizeof(PREFIX) - 1 || memcmp(host.base, PREFIX, sizeof(PREFIX) - 1) != 0)
        return vhttp_url_host_to_sun_err_is_not_unix_socket;

    if (host.len - sizeof(PREFIX) - 1 >= sizeof(sa->sun_path))
        return "unix-domain socket path is too long";

    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    memcpy(sa->sun_path, host.base + sizeof(PREFIX) - 1, host.len - (sizeof(PREFIX) - 1));
    return NULL;

#undef PREFIX
}

const char vhttp_url_host_to_sun_err_is_not_unix_socket[] = "supplied name does not look like an unix-domain socket";

int vhttp_url_init_with_hostport(vhttp_url_t *url, vhttp_mem_pool_t *pool, const vhttp_url_scheme_t *scheme, vhttp_iovec_t host,
                               uint16_t port, vhttp_iovec_t path)
{
    url->scheme = scheme;
    url->path = path;

    if (port == scheme->default_port) {
        url->_port = 65535;
        url->authority = vhttp_strdup(pool, host.base, host.len);
        url->host = url->authority;
    } else {
        url->_port = port;
        char _port[sizeof(vhttp_UINT16_LONGEST_STR)];
        int port_len = sprintf(_port, "%" PRIu16, port);
        if (port_len < 0)
            return -1;

        url->authority.len = host.len + 1 + port_len;
        url->authority.base = pool == NULL ? vhttp_mem_alloc(url->authority.len) : vhttp_mem_alloc_pool(pool, char, url->authority.len);
        memcpy(url->authority.base, host.base, host.len);
        memcpy(url->authority.base + host.len, ":", 1);
        memcpy(url->authority.base + host.len + 1, _port, port_len);
        url->host = vhttp_iovec_init(url->authority.base, url->authority.len - 1 - port_len);
    }

    return 0;
}

int vhttp_url_init_with_sun_path(vhttp_url_t *url, vhttp_mem_pool_t *pool, const vhttp_url_scheme_t *scheme, vhttp_iovec_t sun_path,
                               vhttp_iovec_t path)
{
    url->scheme = scheme;
    url->path = path;
    url->_port = 65535;

#define PREFIX "[unix:"
#define SUFFIX "]"
    url->authority.len = strlen(PREFIX SUFFIX) + sun_path.len;
    url->authority.base = pool == NULL ? vhttp_mem_alloc(url->authority.len) : vhttp_mem_alloc_pool(pool, char, url->authority.len);
    memcpy(url->authority.base, PREFIX, sizeof(PREFIX) - 1);
    memcpy(url->authority.base + sizeof(PREFIX) - 1, sun_path.base, sun_path.len);
    memcpy(url->authority.base + url->authority.len - 1, SUFFIX, sizeof(SUFFIX) - 1);
#undef PREFIX
#undef SUFFIX

    url->host = vhttp_iovec_init(url->authority.base + 1, url->authority.len - 2);

    return 0;
}
