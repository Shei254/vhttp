/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#ifndef vhttp__http2__scheduler_h
#define vhttp__http2__scheduler_h

#include <assert.h>
#include "vhttp/linklist.h"
#include "vhttp/memory.h"

typedef struct st_vhttp_http2_scheduler_queue_node_t {
    vhttp_linklist_t _link;
    size_t _deficit;
} vhttp_http2_scheduler_queue_node_t;

typedef struct st_vhttp_http2_scheduler_queue_t vhttp_http2_scheduler_queue_t;

/**
 * resembles a node in the dependency tree; i.e. assigned for each HTTP/2 stream (as a member of openref), or the root of the tree
 * associated to the connection
 */
typedef struct st_vhttp_http2_scheduler_node_t {
    struct st_vhttp_http2_scheduler_node_t *_parent; /* NULL if root */
    vhttp_linklist_t _all_refs;                      /* list of nodes */
    vhttp_http2_scheduler_queue_t *_queue;           /* priority list (NULL if _all_refs is empty) */
} vhttp_http2_scheduler_node_t;

/**
 * the entry to be scheduled; is assigned for every HTTP/2 stream.
 */
typedef struct st_vhttp_http2_scheduler_openref_t {
    vhttp_http2_scheduler_node_t node;
    uint16_t weight;
    vhttp_linklist_t _all_link; /* linked to _all_refs */
    size_t _active_cnt;       /* COUNT(active_streams_in_dependents) + _self_is_active */
    int _self_is_active;
    vhttp_http2_scheduler_queue_node_t _queue_node;
    int _is_relocated; /* indicates whether this entry is sent to _recently_closed_stream */
} vhttp_http2_scheduler_openref_t;

/**
 * callback called by vhttp_http2_scheduler_run.
 * @param ref reference to an active stream that should consume resource
 * @param still_is_active [out] flag to indicate whether the ref should still be marked as active after returning from the function
 * @param cb_arg value of cb_arg passed to vhttp_http2_scheduler_run
 * @return non-zero value to stop traversing through the tree, or 0 to continue
 */
typedef int (*vhttp_http2_scheduler_run_cb)(vhttp_http2_scheduler_openref_t *ref, int *still_is_active, void *cb_arg);

/**
 *
 */
void vhttp_http2_scheduler_init(vhttp_http2_scheduler_node_t *root);

/**
 * disposes of the scheduler.  All open references belonging to the node must be closed before calling this functions.
 */
void vhttp_http2_scheduler_dispose(vhttp_http2_scheduler_node_t *root);
/**
 * opens a reference with given parent as its dependency
 */
void vhttp_http2_scheduler_open(vhttp_http2_scheduler_openref_t *ref, vhttp_http2_scheduler_node_t *parent, uint16_t weight,
                              int exclusive);
/**
 * closes a reference.  All the dependents are raised to become the dependents of the parent of the reference being closed.
 */
void vhttp_http2_scheduler_close(vhttp_http2_scheduler_openref_t *ref);
/**
 * relocates an openref to a different memory location
 */
void vhttp_http2_scheduler_relocate(vhttp_http2_scheduler_openref_t *dst, vhttp_http2_scheduler_openref_t *src);
/**
 * reprioritizes the reference.
 */
void vhttp_http2_scheduler_rebind(vhttp_http2_scheduler_openref_t *ref, vhttp_http2_scheduler_node_t *new_parent, uint16_t weight,
                                int exclusive);
/**
 * tests if the ref is open
 */
static int vhttp_http2_scheduler_is_open(vhttp_http2_scheduler_openref_t *ref);
/**
 * returns weight associated to the reference
 */
static uint16_t vhttp_http2_scheduler_get_weight(vhttp_http2_scheduler_openref_t *ref);
/**
 * returns the parent
 */
static vhttp_http2_scheduler_node_t *vhttp_http2_scheduler_get_parent(vhttp_http2_scheduler_openref_t *ref);
/**
 * activates a reference so that it would be passed back as the argument to the callback of the vhttp_http2_scheduler_run function
 * if any resource should be allocated
 */
void vhttp_http2_scheduler_activate(vhttp_http2_scheduler_openref_t *ref);
/**
 * deactivates a reference while retaining it in the scheduler
 */
void vhttp_http2_scheduler_deactivate(vhttp_http2_scheduler_openref_t *ref);
/**
 * calls the callback of the references linked to the dependency tree one by one, in the order defined by the dependency and the
 * weight.
 */
int vhttp_http2_scheduler_run(vhttp_http2_scheduler_node_t *root, vhttp_http2_scheduler_run_cb cb, void *cb_arg);
/**
 * returns if there are any active entries nodes in the scheduler (may have false positives, but no false negatives)
 */
int vhttp_http2_scheduler_is_active(vhttp_http2_scheduler_node_t *root);
/**
 * returns a parent node with a weight heavier than or equal to the given weight
 * returns `root` if no such parent exists
 *
 * Note: this function (for now) assumes a priority tree generated by Chromium, i.e.
 * - Streams form a linear list of dependencies. Each stream has no more than one child in
 *   dependency tree.
 * - On a dependency tree (list), streams are ordered in the decending order of weight (highest
 *   weight comes first)
 */
vhttp_http2_scheduler_node_t *vhttp_http2_scheduler_find_parent_by_weight(vhttp_http2_scheduler_node_t *root, uint16_t new_weight);

/* inline definitions */

inline int vhttp_http2_scheduler_is_open(vhttp_http2_scheduler_openref_t *ref)
{
    return vhttp_linklist_is_linked(&ref->_all_link);
}

inline uint16_t vhttp_http2_scheduler_get_weight(vhttp_http2_scheduler_openref_t *ref)
{
    return ref->weight;
}

inline vhttp_http2_scheduler_node_t *vhttp_http2_scheduler_get_parent(vhttp_http2_scheduler_openref_t *ref)
{
    return ref->node._parent;
}

#endif
