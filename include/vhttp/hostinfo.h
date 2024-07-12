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
#ifndef vhttp__hostinfo_h
#define vhttp__hostinfo_h

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "vhttp/multithread.h"

/* generic errors (https://tools.ietf.org/html/rfc8499#section-3) */
extern const char vhttp_hostinfo_error_nxdomain[];
extern const char vhttp_hostinfo_error_nodata[];
extern const char vhttp_hostinfo_error_refused[];
extern const char vhttp_hostinfo_error_servfail[];

/* errors specfic to getaddrinfo */
extern const char vhttp_hostinfo_error_gai_addrfamily[];
extern const char vhttp_hostinfo_error_gai_badflags[];
extern const char vhttp_hostinfo_error_gai_family[];
extern const char vhttp_hostinfo_error_gai_memory[];
extern const char vhttp_hostinfo_error_gai_service[];
extern const char vhttp_hostinfo_error_gai_socktype[];
extern const char vhttp_hostinfo_error_gai_system[];
extern const char vhttp_hostinfo_error_gai_other[];

typedef struct st_vhttp_hostinfo_getaddr_req_t vhttp_hostinfo_getaddr_req_t;

typedef void (*vhttp_hostinfo_getaddr_cb)(vhttp_hostinfo_getaddr_req_t *req, const char *errstr, struct addrinfo *res, void *cbdata);

extern size_t vhttp_hostinfo_max_threads;

/**
 * dispatches a (possibly) asynchronous hostname lookup
 */
vhttp_hostinfo_getaddr_req_t *vhttp_hostinfo_getaddr(vhttp_multithread_receiver_t *receiver, vhttp_iovec_t name, vhttp_iovec_t serv,
                                                 int family, int socktype, int protocol, int flags, vhttp_hostinfo_getaddr_cb cb,
                                                 void *cbdata);
/**
 * cancels the request
 */
void vhttp_hostinfo_getaddr_cancel(vhttp_hostinfo_getaddr_req_t *req);

/**
 * function that receives and dispatches the responses
 */
void vhttp_hostinfo_getaddr_receiver(vhttp_multithread_receiver_t *receiver, vhttp_linklist_t *messages);

/**
 * select one entry at random from the response
 */
static struct addrinfo *vhttp_hostinfo_select_one(struct addrinfo *res);

/**
 * equiv. to inet_pton(AF_INET4)
 */
int vhttp_hostinfo_aton(vhttp_iovec_t host, struct in_addr *addr);

/* inline defs */

inline struct addrinfo *vhttp_hostinfo_select_one(struct addrinfo *res)
{
    if (res->ai_next == NULL)
        return res;

    /* count the number of candidates */
    size_t i = 0;
    struct addrinfo *ai = res;
    do {
        ++i;
    } while ((ai = ai->ai_next) != NULL);

    /* choose one, distributed by rand() :-p */
    i = rand() % i;
    for (ai = res; i != 0; ai = ai->ai_next, --i)
        ;
    return ai;
}

#endif
