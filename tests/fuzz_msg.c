/* fuzz_msg.c
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
 * libFuzzer harness for the wire reader (wn_msg) used by every parser. Reads a
 * mix of integers and a length-prefixed vector from arbitrary input; the
 * sticky-error reader must clamp every over-read and never touch memory out of
 * bounds (ASan-instrumented).
 */

#include "wn_msg.h"
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    wn_Reader r;
    word32 take;

    wn_Reader_Init(&r, (const byte*)data, (word32)size);
    (void)wn_Read_U8(&r);
    (void)wn_Read_U16(&r);
    (void)wn_Read_U24(&r);
    take = (size > 0) ? (word32)data[size - 1] : 0;   /* attacker-chosen length */
    (void)wn_Read_Bytes(&r, take);
    (void)wn_Read_U16(&r);
    return 0;
}
