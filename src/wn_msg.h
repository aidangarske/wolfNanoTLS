/* wn_msg.h
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
 * Bounds-checked TLS wire encode/decode primitives. Big-endian integers and
 * length-prefixed vectors per RFC 8446 section 3. Caller-provided buffers; the
 * error sticks so call sites can check once at the end.
 */

#ifndef WN_MSG_H
#define WN_MSG_H

#include "wolfnano.h"

typedef struct wn_Writer {
    byte* buf;
    word32 cap;
    word32 len;
    int err;
} wn_Writer;

typedef struct wn_Reader {
    const byte* buf;
    word32 len;
    word32 pos;
    int err;
} wn_Reader;

WOLFNANO_LOCAL void wn_Writer_Init(wn_Writer* w, byte* buf, word32 cap);
WOLFNANO_LOCAL void wn_Write_U8(wn_Writer* w, byte v);
WOLFNANO_LOCAL void wn_Write_U16(wn_Writer* w, word16 v);
WOLFNANO_LOCAL void wn_Write_U24(wn_Writer* w, word32 v);
WOLFNANO_LOCAL void wn_Write_Bytes(wn_Writer* w, const byte* p, word32 n);
/* Reserve a 1/2/3-byte length, returning the offset to backfill later. */
WOLFNANO_LOCAL word32 wn_Write_LenStart(wn_Writer* w, int lenBytes);
/* Backfill the length at offset to span everything written since. */
WOLFNANO_LOCAL void wn_Write_LenEnd(wn_Writer* w, word32 offset, int lenBytes);

WOLFNANO_LOCAL void wn_Reader_Init(wn_Reader* r, const byte* buf, word32 len);
WOLFNANO_LOCAL byte wn_Read_U8(wn_Reader* r);
WOLFNANO_LOCAL word16 wn_Read_U16(wn_Reader* r);
WOLFNANO_LOCAL word32 wn_Read_U24(wn_Reader* r);
/* Return a pointer to n bytes and advance, or NULL (and set err) if short. */
WOLFNANO_LOCAL const byte* wn_Read_Bytes(wn_Reader* r, word32 n);

#endif /* WN_MSG_H */
