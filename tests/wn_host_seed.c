/* wn_host_seed.c
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

/* Host seed-hook implementation for the PORTABLE_C self-test. The embedded
 * target supplies its own wn_seed (STM32 TRNG / wolfHAL RNG). */

#include <stdlib.h>

int wn_seed(unsigned char* output, unsigned int sz)
{
    arc4random_buf(output, (size_t)sz);
    return 0;
}
