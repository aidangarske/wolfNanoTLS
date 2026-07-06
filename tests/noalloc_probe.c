/* noalloc_probe.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNanoTLS.
 *
 * wolfNanoTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNanoTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Linker-wrap heap interposer for the runtime no-malloc proof (GNU ld --wrap;
 * Linux/CI only). While wn_alloc_watch is set, every allocation path is counted
 * in wn_alloc_count; the real allocator is still called so the program runs to
 * completion. The test arms the watch only around the handshake window (no
 * stdio) and asserts zero allocations.
 */

#include <stdlib.h>
#include <string.h>

int wn_alloc_watch = 0;
unsigned long wn_alloc_count = 0;

extern void* __real_malloc(size_t n);
extern void* __real_calloc(size_t a, size_t b);
extern void* __real_realloc(void* p, size_t n);
extern void* __real_aligned_alloc(size_t align, size_t n);
extern int   __real_posix_memalign(void** p, size_t align, size_t n);
extern char* __real_strdup(const char* s);

void* __wrap_malloc(size_t n)
{
    if (wn_alloc_watch) {
        wn_alloc_count++;
    }
    return __real_malloc(n);
}

void* __wrap_calloc(size_t a, size_t b)
{
    if (wn_alloc_watch) {
        wn_alloc_count++;
    }
    return __real_calloc(a, b);
}

void* __wrap_realloc(void* p, size_t n)
{
    if (wn_alloc_watch) {
        wn_alloc_count++;
    }
    return __real_realloc(p, n);
}

void* __wrap_aligned_alloc(size_t align, size_t n)
{
    if (wn_alloc_watch) {
        wn_alloc_count++;
    }
    return __real_aligned_alloc(align, n);
}

int __wrap_posix_memalign(void** p, size_t align, size_t n)
{
    if (wn_alloc_watch) {
        wn_alloc_count++;
    }
    return __real_posix_memalign(p, align, n);
}

char* __wrap_strdup(const char* s)
{
    if (wn_alloc_watch) {
        wn_alloc_count++;
    }
    return __real_strdup(s);
}
