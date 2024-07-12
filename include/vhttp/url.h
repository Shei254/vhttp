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
#ifndef vhttp__url_h
#define vhttp__url_h

#include <sys/un.h>
#include "vhttp/memory.h"
#include "vhttp/string_.h"

typedef struct st_vhttp_url_scheme_t {
    vhttp_iovec_t name;
    uint16_t default_port;
    int is_ssl;
} vhttp_url_scheme_t;

extern const vhttp_url_scheme_t vhttp_URL_SCHEME_HTTP, vhttp_URL_SCHEME_HTTPS;
extern const vhttp_url_scheme_t vhttp_URL_SCHEME_MASQUE;
/**
 * used by fastcgi handler
 */
extern const vhttp_url_scheme_t vhttp_URL_SCHEME_FASTCGI;

typedef struct st_vhttp_url_t {
    const vhttp_url_scheme_t *scheme;
    vhttp_iovec_t authority; /* i.e. host:port */
    vhttp_iovec_t host;
    vhttp_iovec_t path;
    uint16_t _port;
} vhttp_url_t;

/**
 * retrieves the port number from url
 */
static uint16_t vhttp_url_get_port(const vhttp_url_t *url);
/**
 * removes "..", ".", decodes %xx from a path representation
 * @param pool memory pool to be used in case the path contained references to directories
 * @param path source path
 * @param len source length
 * @param returns offset of '?' within `path` if found, or SIZE_MAX if not
 * @param indexes mapping the normalized version to the input version
 * @return buffer pointing to source, or buffer pointing to an allocated chunk with normalized representation of the given path
 */
vhttp_iovec_t vhttp_url_normalize_path(vhttp_mem_pool_t *pool, const char *path, size_t len, size_t *query_at, size_t **norm_indexes);
/**
 * initializes URL object given scheme, authority, and path
 * @param the output
 * @param scheme scheme
 * @param authority
 * @param path
 * @return 0 if successful
 */
static int vhttp_url_init(vhttp_url_t *url, const vhttp_url_scheme_t *scheme, vhttp_iovec_t authority, vhttp_iovec_t path);

int vhttp_url_init_with_hostport(vhttp_url_t *url, vhttp_mem_pool_t *pool, const vhttp_url_scheme_t *scheme, vhttp_iovec_t host,
                               uint16_t port, vhttp_iovec_t path);
int vhttp_url_init_with_sun_path(vhttp_url_t *url, vhttp_mem_pool_t *pool, const vhttp_url_scheme_t *scheme, vhttp_iovec_t sun_path,
                               vhttp_iovec_t path);

/**
 * Parses absolute URL (either http or https). Upon successful return, `path` attribute of the returned object is guaranteed to be
 * in absolute form (i.e., starts with `/`) so that it can be passed directly to HTTP clients.
 */
int vhttp_url_parse(vhttp_mem_pool_t *pool, const char *url, size_t url_len, vhttp_url_t *result);
/**
 * parses relative URL
 */
int vhttp_url_parse_relative(vhttp_mem_pool_t *pool, const char *url, size_t url_len, vhttp_url_t *result);
/**
 * parses the authority and returns the next position (i.e. start of path)
 * @return pointer to the end of hostport if successful, or NULL if failed.  *port becomes the specified port number or 65535 if not
 */
const char *vhttp_url_parse_hostport(const char *s, size_t len, vhttp_iovec_t *host, uint16_t *port);
/**
 * resolves the URL (stored to `dest` as well as returning the stringified representation (always allocated using pool)
 */
vhttp_iovec_t vhttp_url_resolve(vhttp_mem_pool_t *pool, const vhttp_url_t *base, const vhttp_url_t *relative, vhttp_url_t *dest);
/**
 * resolves the path part of the URL (both the arguments are modified; the result is vhttp_concat(*base, *relative))
 */
void vhttp_url_resolve_path(vhttp_iovec_t *base, vhttp_iovec_t *relative);
/**
 * stringifies the URL
 */
static vhttp_iovec_t vhttp_url_stringify(vhttp_mem_pool_t *pool, const vhttp_url_t *url);
/**
 * copies a URL object (null-terminates all the string elements)
 */
void vhttp_url_copy(vhttp_mem_pool_t *pool, vhttp_url_t *dest, const vhttp_url_t *src);
/**
 * extracts sockaddr_un from host and returns NULL (or returns an error string if failed)
 */
const char *vhttp_url_host_to_sun(vhttp_iovec_t host, struct sockaddr_un *sa);
extern const char vhttp_url_host_to_sun_err_is_not_unix_socket[];

/* inline definitions */

inline int vhttp_url_init(vhttp_url_t *url, const vhttp_url_scheme_t *scheme, vhttp_iovec_t authority, vhttp_iovec_t path)
{
    if (vhttp_url_parse_hostport(authority.base, authority.len, &url->host, &url->_port) != authority.base + authority.len)
        return -1;
    url->scheme = scheme;
    url->authority = authority;
    url->path = path;
    return 0;
}

inline uint16_t vhttp_url_get_port(const vhttp_url_t *url)
{
    return url->_port != 65535 ? url->_port : url->scheme->default_port;
}

inline vhttp_iovec_t vhttp_url_stringify(vhttp_mem_pool_t *pool, const vhttp_url_t *url)
{
    vhttp_url_t tmp;
    return vhttp_url_resolve(pool, url, NULL, &tmp);
}

static inline int vhttp_url_host_is_unix_path(vhttp_iovec_t host)
{
    if (host.len < 5) {
        return 0;
    }
    return vhttp_memis(host.base, 5, vhttp_STRLIT("unix:"));
}

/**
 * Compares to hostnames, taking into account whether they contain a
 * unix path (the comparison will be case sensitive) or not.
 */
static inline int vhttp_url_hosts_are_equal(const vhttp_url_t *url_a, const vhttp_url_t *url_b)
{
    if (url_a->host.len != url_b->host.len)
        return 0;

    if (vhttp_url_host_is_unix_path(url_a->host))
        return vhttp_memis(url_a->host.base, url_a->host.len, url_b->host.base, url_b->host.len);
    else
        return vhttp_lcstris(url_a->host.base, url_a->host.len, url_b->host.base, url_b->host.len);
}

#endif
