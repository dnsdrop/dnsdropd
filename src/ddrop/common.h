#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CS__EXPORT
#define CS__EXPORT __attribute__ ((visibility("default")))
#endif

static void *
mm__dup_(const void * src, size_t size)
{
    void * mem = calloc(1, size);

    return mem ? memcpy(mem, src, size) : NULL;
}

#define mm__alloc_(type, ...) \
    (type *)mm__dup_((type[]) {__VA_ARGS__ }, sizeof(type))


#define ddrop_likely(x)                __builtin_expect(!!(x), 1)
#define ddrop_unlikely(x)              __builtin_expect(!!(x), 0)

#define ddrop_safe_free(_var, _freefn) do { \
        _freefn((_var));                    \
        (_var) = NULL;                      \
}  while (0)

#define ddrop_assert(x)                                               \
    do {                                                              \
        if (ddrop_unlikely(!(x))) {                                   \
            fprintf(stderr, "Assertion failed: %s (%s:%s:%d)\n", # x, \
                    __func__, __FILE__, __LINE__);                    \
            fflush(stderr);                                           \
            abort();                                                  \
        }                                                             \
    } while (0)

#define ddrop_alloc_assert(x)                             \
    do {                                                  \
        if (ddrop_unlikely(!x)) {                         \
            fprintf(stderr, "Out of memory (%s:%s:%d)\n", \
                    __func__, __FILE__, __LINE__);        \
            fflush(stderr);                               \
            abort();                                      \
        }                                                 \
    } while (0)

#define ddrop_assert_fmt(x, fmt, ...)                                    \
    do {                                                                 \
        if (ddrop_unlikely(!(x))) {                                      \
            fprintf(stderr, "Assertion failed: %s (%s:%s:%d) " fmt "\n", \
                    # x, __func__, __FILE__, __LINE__, __VA_ARGS__);     \
            fflush(stderr);                                              \
            abort();                                                     \
        }                                                                \
    } while (0)

#define ddrop_errno_assert(x)                       \
    do {                                            \
        if (ddrop_unlikely(!(x))) {                 \
            fprintf(stderr, "%s [%d] (%s:%s:%d)\n", \
                    strerror(errno), errno,         \
                    __func__, __FILE__, __LINE__);  \
            fflush(stderr);                         \
            abort();                                \
        }                                           \
    } while (0)


#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif



