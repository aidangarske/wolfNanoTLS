/* msg_test.c
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

/* Wire encode/decode primitive tests: integers, byte vectors, length backfill,
 * round-trip, and bounds checking. */

#include "wn_msg.h"
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

int main(void)
{
    static const byte expect[8] = {
        0xab, 0x12, 0x34, 0x01, 0x02, 0x03, 0x68, 0x69
    };
    byte buf[64];
    wn_Writer w;
    wn_Reader r;
    word32 off;
    word16 u16;
    word32 u24;
    const byte* p;
    byte u8;
    int ok;

    printf("wolfNano wire primitive tests\n");

    wn_Writer_Init(&w, buf, sizeof(buf));
    wn_Write_U8(&w, 0xab);
    wn_Write_U16(&w, 0x1234);
    wn_Write_U24(&w, 0x010203);
    wn_Write_Bytes(&w, (const byte*)"hi", 2);
    check((w.err == 0) && (w.len == 8) && (XMEMCMP(buf, expect, 8) == 0),
          "write u8/u16/u24/bytes");

    /* length backfill: header type + 3-byte length spanning a 4-byte body */
    wn_Writer_Init(&w, buf, sizeof(buf));
    wn_Write_U8(&w, 0x16);
    off = wn_Write_LenStart(&w, 3);
    wn_Write_U16(&w, 0xeeff);
    wn_Write_U16(&w, 0xaabb);
    wn_Write_LenEnd(&w, off, 3);
    ok = (w.err == 0) && (w.len == 8) &&
         (buf[0] == 0x16) &&
         (buf[1] == 0x00) && (buf[2] == 0x00) && (buf[3] == 0x04);
    check(ok, "3-byte length backfill");

    wn_Reader_Init(&r, buf, w.len);
    u8  = wn_Read_U8(&r);
    u24 = wn_Read_U24(&r);
    u16 = wn_Read_U16(&r);
    p   = wn_Read_Bytes(&r, 2);
    check((r.err == 0) && (u8 == 0x16) && (u24 == 4) && (u16 == 0xeeff) &&
          (p != NULL) && (p[0] == 0xaa) && (p[1] == 0xbb),
          "read back round-trips");

    /* over-read latches err */
    (void)wn_Read_U16(&r);
    check(r.err == 1, "short read sets err");

    /* write overflow latches err */
    wn_Writer_Init(&w, buf, 2);
    wn_Write_U24(&w, 0x010203);
    check(w.err == 1, "write overflow sets err");

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
