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
#ifndef vhttp__linklist_h
#define vhttp__linklist_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>

/**
 * linklist
 * The structure is used to represent both nodes and the head of the list.
 * Nodes should be zero-filled upon initialization.
 * Heads should be initialized by calling vhttp_linklist_init_anchor.
 */
typedef struct st_vhttp_linklist_t {
    struct st_vhttp_linklist_t *next;
    struct st_vhttp_linklist_t *prev;
} vhttp_linklist_t;

/**
 * initializes the anchor (i.e. head) of a linked list
 */
static void vhttp_linklist_init_anchor(vhttp_linklist_t *anchor);
/**
 * tests if the list is empty
 */
static int vhttp_linklist_is_empty(vhttp_linklist_t *anchor);
/**
 * tests if the node is linked to a list
 */
static int vhttp_linklist_is_linked(vhttp_linklist_t *node);
/**
 * inserts a node to the linked list
 * @param pos insert position; the node will be inserted before pos
 * @param node the node to be inserted
 */
static void vhttp_linklist_insert(vhttp_linklist_t *pos, vhttp_linklist_t *node);
/**
 * inserts all the elements of list before pos (list becomes empty)
 */
static void vhttp_linklist_insert_list(vhttp_linklist_t *pos, vhttp_linklist_t *list);
/**
 * unlinks a node from the linked list
 */
static void vhttp_linklist_unlink(vhttp_linklist_t *node);

/* inline defs */

inline void vhttp_linklist_init_anchor(vhttp_linklist_t *anchor)
{
    anchor->next = anchor->prev = anchor;
}

inline int vhttp_linklist_is_linked(vhttp_linklist_t *node)
{
    return node->next != NULL;
}

inline int vhttp_linklist_is_empty(vhttp_linklist_t *anchor)
{
    return anchor->next == anchor;
}

inline void vhttp_linklist_insert(vhttp_linklist_t *pos, vhttp_linklist_t *node)
{
    assert(!vhttp_linklist_is_linked(node));

    node->prev = pos->prev;
    node->next = pos;
    node->prev->next = node;
    node->next->prev = node;
}

inline void vhttp_linklist_insert_list(vhttp_linklist_t *pos, vhttp_linklist_t *list)
{
    if (vhttp_linklist_is_empty(list))
        return;
    list->next->prev = pos->prev;
    list->prev->next = pos;
    pos->prev->next = list->next;
    pos->prev = list->prev;
    vhttp_linklist_init_anchor(list);
}

inline void vhttp_linklist_unlink(vhttp_linklist_t *node)
{
    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = node->prev = NULL;
}

#ifdef __cplusplus
}
#endif

#endif
