/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Justin Zhu
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
#ifndef vhttp__memory_h
#define vhttp__memory_h

#ifdef __sun__
#include <alloca.h>
#endif
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#define vhttp_STRUCT_FROM_MEMBER(s, m, p) ((s *)((char *)(p)-offsetof(s, m)))
#define vhttp_ALIGNOF(type) (__alignof__(type))

#if __GNUC__ >= 3
#define vhttp_LIKELY(x) __builtin_expect(!!(x), 1)
#define vhttp_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define vhttp_LIKELY(x) (x)
#define vhttp_UNLIKELY(x) (x)
#endif

#ifdef __GNUC__
#define vhttp_GNUC_VERSION ((__GNUC__ << 16) | (__GNUC_MINOR__ << 8) | __GNUC_PATCHLEVEL__)
#else
#define vhttp_GNUC_VERSION 0
#endif

#if __STDC_VERSION__ >= 201112L
#define vhttp_NORETURN _Noreturn
#elif defined(__clang__) || defined(__GNUC__) && vhttp_GNUC_VERSION >= 0x20500
// noreturn was not defined before gcc 2.5
#define vhttp_NORETURN __attribute__((noreturn))
#else
#define vhttp_NORETURN
#endif

#if !defined(__clang__) && defined(__GNUC__) && vhttp_GNUC_VERSION >= 0x40900
// returns_nonnull was seemingly not defined before gcc 4.9 (exists in 4.9.1 but not in 4.8.2)
#define vhttp_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define vhttp_RETURNS_NONNULL
#endif

#define vhttp_TO__STR(n) #n
#define vhttp_TO_STR(n) vhttp_TO__STR(n)

#define vhttp_BUILD_ASSERT(condition) ((void)sizeof(char[2 * !!(!__builtin_constant_p(condition) || (condition)) - 1]))

/**
 * library users can use their own log method by define this macro
 */
#ifndef vhttp_error_printf
#define vhttp_error_printf(...) fprintf(stderr, __VA_ARGS__)
#endif

typedef struct st_vhttp_buffer_prototype_t vhttp_buffer_prototype_t;

/**
 * buffer structure compatible with iovec
 */
typedef struct st_vhttp_iovec_t {
    char *base;
    size_t len;
} vhttp_iovec_t;

#define vhttp_VECTOR(type)                                                                                                           \
    struct {                                                                                                                       \
        type *entries;                                                                                                             \
        size_t size;                                                                                                               \
        size_t capacity;                                                                                                           \
    }

typedef vhttp_VECTOR(void) vhttp_vector_t;
typedef vhttp_VECTOR(uint8_t) vhttp_byte_vector_t;
typedef vhttp_VECTOR(vhttp_iovec_t) vhttp_iovec_vector_t;

typedef struct st_vhttp_mem_recycle_conf_t {
    size_t memsize;
    uint8_t align_bits;
} vhttp_mem_recycle_conf_t;

typedef struct st_vhttp_mem_recycle_t {
    const vhttp_mem_recycle_conf_t *conf;
    vhttp_VECTOR(void *) chunks;
    size_t low_watermark;
} vhttp_mem_recycle_t;

struct st_vhttp_mem_pool_shared_entry_t {
    size_t refcnt;
    void (*dispose)(void *);
    char bytes[1];
};

/**
 * the memory pool
 */
union un_vhttp_mem_pool_chunk_t;
typedef struct st_vhttp_mem_pool_t {
    union un_vhttp_mem_pool_chunk_t *chunks;
    size_t chunk_offset;
    struct st_vhttp_mem_pool_shared_ref_t *shared_refs;
    struct st_vhttp_mem_pool_direct_t *directs;
} vhttp_mem_pool_t;

/**
 * buffer used to store incoming / outgoing octets
 */
typedef struct st_vhttp_buffer_t {
    /**
     * when `bytes` != NULL (and therefore `size` != 0), the capacity of the buffer, or otherwise the minimum initial capacity in
     * case of a prototype, or the desired next capacity if not a prototype.
     */
    size_t capacity;
    /**
     * amount of the data available
     */
    size_t size;
    /**
     * pointer to the start of the data (or NULL if is pointing to a prototype)
     */
    char *bytes;
    /**
     * prototype (or NULL if the instance is part of the prototype)
     */
    vhttp_buffer_prototype_t *_prototype;
    /**
     * file descriptor (if not -1, vhttp_buffer_t is a memory map of the contents of this file descriptor)
     */
    int _fd;
    /**
     * memory used to store data
     */
    char _buf[1];
} vhttp_buffer_t;

#define vhttp_TMP_FILE_TEMPLATE_MAX 256
typedef struct st_vhttp_buffer_mmap_settings_t {
    size_t threshold;
    char fn_template[vhttp_TMP_FILE_TEMPLATE_MAX];
} vhttp_buffer_mmap_settings_t;

struct st_vhttp_buffer_prototype_t {
    vhttp_buffer_t _initial_buf;
    vhttp_buffer_mmap_settings_t *mmap_settings;
};

typedef struct st_vhttp_doublebuffer_t {
    vhttp_buffer_t *buf;
    unsigned char inflight : 1;
    size_t _bytes_inflight;
} vhttp_doublebuffer_t;

extern void *(*volatile vhttp_mem__set_secure)(void *, int, size_t);

/**
 * prints an error message and aborts. vhttp_fatal can be modified by setting the function pointer it expands to, which is vhttp__fatal.
 */
extern vhttp_NORETURN void (*vhttp__fatal)(const char *file, int line, const char *msg, ...) __attribute__((format(printf, 3, 4)));
#ifndef vhttp_fatal
#define vhttp_fatal(...) vhttp__fatal(__FILE__, __LINE__, __VA_ARGS__)
#endif

void vhttp_perror(const char *msg);
char *vhttp_strerror_r(int err, char *buf, size_t len);

/**
 * A version of memcpy that can take a NULL @src to avoid UB
 */
static void *vhttp_memcpy(void *dst, const void *src, size_t n);
/**
 * constructor for vhttp_iovec_t
 */
static vhttp_iovec_t vhttp_iovec_init(const void *base, size_t len);
/**
 * wrapper of malloc; allocates given size of memory or dies if impossible
 */
vhttp_RETURNS_NONNULL static void *vhttp_mem_alloc(size_t sz);
/**
 * wrapper of posix_memalign; if alignment is zero, calls `malloc`
 */
vhttp_RETURNS_NONNULL static void *vhttp_mem_aligned_alloc(size_t alignment, size_t sz);
/**
 * warpper of realloc; reallocs the given chunk or dies if impossible
 */
static void *vhttp_mem_realloc(void *oldp, size_t sz);

/**
 * allocates memory using the reusing allocator
 */
void *vhttp_mem_alloc_recycle(vhttp_mem_recycle_t *allocator);
/**
 * returns the memory to the reusing allocator
 */
void vhttp_mem_free_recycle(vhttp_mem_recycle_t *allocator, void *p);
/**
 * release all the memory chunks cached in input allocator to system
 */
void vhttp_mem_clear_recycle(vhttp_mem_recycle_t *allocator, int full);
/**
 *
 */
static int vhttp_mem_recycle_is_empty(vhttp_mem_recycle_t *allocator);

/**
 * initializes the memory pool.
 */
void vhttp_mem_init_pool(vhttp_mem_pool_t *pool);
/**
 * clears the memory pool.
 * Applications may dispose the pool after calling the function or reuse it without calling vhttp_mem_init_pool.
 */
void vhttp_mem_clear_pool(vhttp_mem_pool_t *pool);
/**
 * allocates given size of memory from the memory pool, or dies if impossible
 */
#define vhttp_mem_alloc_pool(pool, type, cnt) vhttp_mem_alloc_pool_aligned(pool, vhttp_ALIGNOF(type), sizeof(type) * (cnt))
/**
 * allocates given size of memory from pool using given alignment
 */
static void *vhttp_mem_alloc_pool_aligned(vhttp_mem_pool_t *pool, size_t alignment, size_t size);
void *vhttp_mem__do_alloc_pool_aligned(vhttp_mem_pool_t *pool, size_t alignment, size_t size);
/**
 * allocates a ref-counted chunk of given size from the memory pool, or dies if impossible.
 * The ref-count of the returned chunk is 1 regardless of whether or not the chunk is linked to a pool.
 * @param pool pool to which the allocated chunk should be linked (or NULL to allocate an orphan chunk)
 */
void *vhttp_mem_alloc_shared(vhttp_mem_pool_t *pool, size_t sz, void (*dispose)(void *));
/**
 * links a ref-counted chunk to a memory pool.
 * The ref-count of the chunk will be decremented when the pool is cleared.
 * It is permitted to link a chunk more than once to a single pool.
 */
void vhttp_mem_link_shared(vhttp_mem_pool_t *pool, void *p);
/**
 * increments the reference count of a ref-counted chunk.
 */
static void vhttp_mem_addref_shared(void *p);
/**
 * decrements the reference count of a ref-counted chunk.
 * The chunk gets freed when the ref-count reaches zero.
 */
static int vhttp_mem_release_shared(void *p);
/**
 * frees unused memory being pooled for recycling
 */
void vhttp_buffer_clear_recycle(int full);
/**
 *
 */
int vhttp_buffer_recycle_is_empty(void);
/**
 * initialize the buffer using given prototype.
 */
static void vhttp_buffer_init(vhttp_buffer_t **buffer, vhttp_buffer_prototype_t *prototype);
/**
 * calls the appropriate function to free the resources associated with the buffer
 */
void vhttp_buffer__do_free(vhttp_buffer_t *buffer);
/**
 * disposes of the buffer
 */
static void vhttp_buffer_dispose(vhttp_buffer_t **buffer);
/**
 * allocates a buffer with vhttp_buffer_try_reserve. aborts on allocation failure.
 * @return buffer to which the next data should be stored
 */
vhttp_iovec_t vhttp_buffer_reserve(vhttp_buffer_t **inbuf, size_t min_guarantee);
/**
 * allocates a buffer.
 * @param inbuf - pointer to a pointer pointing to the structure (set *inbuf to NULL to allocate a new buffer)
 * @param min_guarantee minimum number of additional bytes to reserve
 * @return buffer to which the next data should be stored
 * @note When called against a new buffer, the function returns a buffer twice the size of requested guarantee.  The function uses
 * exponential backoff for already-allocated buffers.
 */
vhttp_iovec_t vhttp_buffer_try_reserve(vhttp_buffer_t **inbuf, size_t min_guarantee) __attribute__((warn_unused_result));
/**
 * copies @len bytes from @src to @dst, calling vhttp_buffer_reserve. aborts on allocation failure.
 */
static void vhttp_buffer_append(vhttp_buffer_t **dst, const void *src, size_t len);
/**
 * variant of vhttp_buffer_append that does not abort on failure
 * @return a boolean indicating if allocation has succeeded
 */
static int vhttp_buffer_try_append(vhttp_buffer_t **dst, const void *src, size_t len) __attribute__((warn_unused_result));
/**
 * throws away given size of the data from the buffer.
 * @param delta number of octets to be drained from the buffer
 */
void vhttp_buffer_consume(vhttp_buffer_t **inbuf, size_t delta);
/**
 * throws away entire data being store in the buffer
 * @param record_capacity if set to true, retains the current capacity of the buffer, and when memory reservation is requested the
 *                        next time, allocates memory as large as the recorded capacity. Otherwise, memory would be reserved based
 *                        on the value of `min_guarantee`, current size, and the prototype.
 */
void vhttp_buffer_consume_all(vhttp_buffer_t **inbuf, int record_capacity);
/**
 * resets the buffer prototype
 */
static void vhttp_buffer_set_prototype(vhttp_buffer_t **buffer, vhttp_buffer_prototype_t *prototype);
/**
 * registers a buffer to memory pool, so that it would be freed when the pool is flushed.  Note that the buffer cannot be resized
 * after it is linked.
 */
static void vhttp_buffer_link_to_pool(vhttp_buffer_t *buffer, vhttp_mem_pool_t *pool);
void vhttp_buffer__dispose_linked(void *p);
/**
 *
 */
static void vhttp_doublebuffer_init(vhttp_doublebuffer_t *db, vhttp_buffer_prototype_t *prototype);
/**
 *
 */
static void vhttp_doublebuffer_dispose(vhttp_doublebuffer_t *db);
/**
 * Given a double buffer and a pointer to a buffer to which the caller is writing data, returns a vector containing data to be sent
 * (e.g., by calling `vhttp_send`).  `max_bytes` designates the maximum size of the vector to be returned.  When the double buffer is
 * empty, `*receiving` is moved to the double buffer, and upon return `*receiving` will contain an empty buffer to which the caller
 * should append new data.
 */
static vhttp_iovec_t vhttp_doublebuffer_prepare(vhttp_doublebuffer_t *db, vhttp_buffer_t **receiving, size_t max_bytes);
/**
 * Marks that empty data is inflight. This function can be called when making preparations to call `vhttp_send` but when only the HTTP
 * response header fields are available.
 */
static void vhttp_doublebuffer_prepare_empty(vhttp_doublebuffer_t *db);
/**
 * Consumes bytes being marked as inflight (by previous call to `vhttp_doublebuffer_prepare`). The intended design pattern is to call
 * this function and then the generator's `do_send` function in the `do_proceed` callback. See lib/handler/fastcgi.c.
 */
static void vhttp_doublebuffer_consume(vhttp_doublebuffer_t *db);
/**
 * grows the vector so that it could store at least new_capacity elements of given size (or dies if impossible).
 * @param pool memory pool that the vector is using
 * @param vector the vector
 * @param element_size size of the elements stored in the vector
 * @param new_capacity the capacity of the buffer after the function returns
 */
#define vhttp_vector_reserve(pool, vector, new_capacity)                                                                             \
    vhttp_vector__reserve((pool), (vhttp_vector_t *)(void *)(vector), vhttp_ALIGNOF((vector)->entries[0]), sizeof((vector)->entries[0]), \
                        (new_capacity))
static void vhttp_vector__reserve(vhttp_mem_pool_t *pool, vhttp_vector_t *vector, size_t alignment, size_t element_size,
                                size_t new_capacity);
void vhttp_vector__expand(vhttp_mem_pool_t *pool, vhttp_vector_t *vector, size_t alignment, size_t element_size, size_t new_capacity);
/**
 * erase the entry at given index from the vector
 */
#define vhttp_vector_erase(vector, index) vhttp_vector__erase((vhttp_vector_t *)(void *)(vector), sizeof((vector)->entries[0]), (index))
static void vhttp_vector__erase(vhttp_vector_t *vector, size_t element_size, size_t index);

/**
 * tests if target chunk (target_len bytes long) is equal to test chunk (test_len bytes long)
 */
static int vhttp_memis(const void *target, size_t target_len, const void *test, size_t test_len);

/**
 * variant of memchr that searches the string from tail
 */
static void *vhttp_memrchr(const void *s, int c, size_t n);

/**
 * secure memset
 */
static void *vhttp_mem_set_secure(void *b, int c, size_t len);

/**
 * swaps contents of memory
 */
void vhttp_mem_swap(void *x, void *y, size_t len);

/**
 * emits hexdump of given buffer to fp
 */
void vhttp_dump_memory(FILE *fp, const char *buf, size_t len);

/**
 * appends an element to a NULL-terminated list allocated using malloc
 */
void vhttp_append_to_null_terminated_list(void ***list, void *element);

extern __thread vhttp_mem_recycle_t vhttp_mem_pool_allocator;
extern size_t vhttp_mmap_errors;

/* inline defs */

inline void *vhttp_memcpy(void *dst, const void *src, size_t n)
{
    if (src != NULL)
        return memcpy(dst, src, n);
    else if (n != 0)
        vhttp_fatal("null pointer passed to memcpy");
    return dst;
}

inline int vhttp_mem_recycle_is_empty(vhttp_mem_recycle_t *allocator)
{
    return allocator->chunks.size == 0;
}

inline vhttp_iovec_t vhttp_iovec_init(const void *base, size_t len)
{
    /* intentionally declared to take a "const void*" since it may contain any type of data and since _some_ buffers are constant */
    vhttp_iovec_t buf;
    buf.base = (char *)base;
    buf.len = len;
    return buf;
}

inline void *vhttp_mem_alloc(size_t sz)
{
    void *p = malloc(sz);
    if (p == NULL)
        vhttp_fatal("no memory");
    return p;
}

inline void *vhttp_mem_aligned_alloc(size_t alignment, size_t sz)
{
    if (alignment <= 1)
        return vhttp_mem_alloc(sz);

    void *p;
    if (posix_memalign(&p, alignment, sz) != 0)
        vhttp_fatal("no memory");
    return p;
}

inline void *vhttp_mem_realloc(void *oldp, size_t sz)
{
    void *newp = realloc(oldp, sz);
    if (newp == NULL) {
        vhttp_fatal("no memory");
        return oldp;
    }
    return newp;
}

inline void *vhttp_mem_alloc_pool_aligned(vhttp_mem_pool_t *pool, size_t alignment, size_t size)
{
    /* C11 6.2.8: "Every valid alignment value shall be a nonnegative integral power of two"; assert will be resolved at compile-
     * time for performance-sensitive cases */
    assert(alignment != 0 && (alignment & (alignment - 1)) == 0);
    return vhttp_mem__do_alloc_pool_aligned(pool, alignment, size);
}

inline void vhttp_mem_addref_shared(void *p)
{
    struct st_vhttp_mem_pool_shared_entry_t *entry = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_mem_pool_shared_entry_t, bytes, p);
    assert(entry->refcnt != 0);
    ++entry->refcnt;
}

inline int vhttp_mem_release_shared(void *p)
{
    struct st_vhttp_mem_pool_shared_entry_t *entry = vhttp_STRUCT_FROM_MEMBER(struct st_vhttp_mem_pool_shared_entry_t, bytes, p);
    assert(entry->refcnt != 0);
    if (--entry->refcnt == 0) {
        if (entry->dispose != NULL)
            entry->dispose(entry->bytes);
        free(entry);
        return 1;
    }
    return 0;
}

inline void vhttp_buffer_init(vhttp_buffer_t **buffer, vhttp_buffer_prototype_t *prototype)
{
    *buffer = &prototype->_initial_buf;
}

inline void vhttp_buffer_dispose(vhttp_buffer_t **_buffer)
{
    vhttp_buffer_t *buffer = *_buffer;
    *_buffer = NULL;
    if (buffer->_prototype != NULL)
        vhttp_buffer__do_free(buffer);
}

inline void vhttp_buffer_set_prototype(vhttp_buffer_t **buffer, vhttp_buffer_prototype_t *prototype)
{
    if ((*buffer)->_prototype != NULL)
        (*buffer)->_prototype = prototype;
    else
        *buffer = &prototype->_initial_buf;
}

inline void vhttp_buffer_link_to_pool(vhttp_buffer_t *buffer, vhttp_mem_pool_t *pool)
{
    vhttp_buffer_t **slot = (vhttp_buffer_t **)vhttp_mem_alloc_shared(pool, sizeof(*slot), vhttp_buffer__dispose_linked);
    *slot = buffer;
}

inline void vhttp_buffer_append(vhttp_buffer_t **dst, const void *src, size_t len)
{
    vhttp_iovec_t buf = vhttp_buffer_reserve(dst, len);
    vhttp_memcpy(buf.base, src, len);
    (*dst)->size += len;
}

inline int vhttp_buffer_try_append(vhttp_buffer_t **dst, const void *src, size_t len)
{
    vhttp_iovec_t buf = vhttp_buffer_try_reserve(dst, len);
    if (buf.base == NULL)
        return 0;
    vhttp_memcpy(buf.base, src, len);
    (*dst)->size += len;
    return 1;
}

inline void vhttp_doublebuffer_init(vhttp_doublebuffer_t *db, vhttp_buffer_prototype_t *prototype)
{
    vhttp_buffer_init(&db->buf, prototype);
    db->inflight = 0;
    db->_bytes_inflight = 0;
}

inline void vhttp_doublebuffer_dispose(vhttp_doublebuffer_t *db)
{
    vhttp_buffer_dispose(&db->buf);
}

inline vhttp_iovec_t vhttp_doublebuffer_prepare(vhttp_doublebuffer_t *db, vhttp_buffer_t **receiving, size_t max_bytes)
{
    assert(!db->inflight);
    assert(max_bytes != 0);

    if (db->buf->size == 0) {
        if ((*receiving)->size == 0)
            return vhttp_iovec_init(NULL, 0);
        /* swap buffers */
        vhttp_buffer_t *t = db->buf;
        db->buf = *receiving;
        *receiving = t;
    }
    if ((db->_bytes_inflight = db->buf->size) > max_bytes)
        db->_bytes_inflight = max_bytes;
    db->inflight = 1;
    return vhttp_iovec_init(db->buf->bytes, db->_bytes_inflight);
}

inline void vhttp_doublebuffer_prepare_empty(vhttp_doublebuffer_t *db)
{
    assert(!db->inflight);
    db->inflight = 1;
}

inline void vhttp_doublebuffer_consume(vhttp_doublebuffer_t *db)
{
    assert(db->inflight);
    db->inflight = 0;

    if (db->buf->size == db->_bytes_inflight) {
        vhttp_buffer_consume_all(&db->buf, 1);
    } else {
        vhttp_buffer_consume(&db->buf, db->_bytes_inflight);
    }
    db->_bytes_inflight = 0;
}

inline void vhttp_vector__reserve(vhttp_mem_pool_t *pool, vhttp_vector_t *vector, size_t alignment, size_t element_size,
                                size_t new_capacity)
{
    if (vector->capacity < new_capacity) {
        vhttp_vector__expand(pool, vector, alignment, element_size, new_capacity);
    }
}

inline void vhttp_vector__erase(vhttp_vector_t *vector, size_t element_size, size_t index)
{
    char *entries = (char *)vector->entries;
    memmove(entries + element_size * index, entries + element_size * (index + 1), element_size * (vector->size - index - 1));
    --vector->size;
}

inline int vhttp_memis(const void *_target, size_t target_len, const void *_test, size_t test_len)
{
    const char *target = (const char *)_target, *test = (const char *)_test;
    if (target_len != test_len)
        return 0;
    if (target_len == 0)
        return 1;
    if (target[0] != test[0])
        return 0;
    return memcmp(target + 1, test + 1, test_len - 1) == 0;
}

inline void *vhttp_memrchr(const void *s, int c, size_t n)
{
    if (n != 0) {
        const char *p = (const char *)s + n;
        do {
            if (*--p == c)
                return (void *)p;
        } while (p != s);
    }
    return NULL;
}

inline void *vhttp_mem_set_secure(void *b, int c, size_t len)
{
    return vhttp_mem__set_secure(b, c, len);
}

#ifdef __cplusplus
}
#endif

#endif
