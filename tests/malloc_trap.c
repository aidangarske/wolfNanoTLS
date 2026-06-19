/* malloc_trap.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNano.
 *
 * wolfNano is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNano is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Linker-wrap heap interposer for the runtime no-malloc proof. Built with
 * -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc. While wn_trap_armed is set,
 * every heap allocation is counted in wn_trap_hits; the real allocator is still
 * called so the program runs to completion. The test arms the trap only around
 * the handshake crypto path (no stdio in that window) and asserts zero hits.
 */

#include <stdlib.h>

int wn_trap_armed = 0;
unsigned long wn_trap_hits = 0;

extern void* __real_malloc(size_t n);
extern void* __real_calloc(size_t a, size_t b);
extern void* __real_realloc(void* p, size_t n);

void* __wrap_malloc(size_t n)
{
    if (wn_trap_armed) {
        wn_trap_hits++;
    }
    return __real_malloc(n);
}

void* __wrap_calloc(size_t a, size_t b)
{
    if (wn_trap_armed) {
        wn_trap_hits++;
    }
    return __real_calloc(a, b);
}

void* __wrap_realloc(void* p, size_t n)
{
    if (wn_trap_armed) {
        wn_trap_hits++;
    }
    return __real_realloc(p, n);
}
