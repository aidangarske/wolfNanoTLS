/* parser_negative_test.c
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
 * Negative / malformed-input tests for the TLS 1.3 ServerHello parser.
 * Each case feeds deliberately broken input and asserts a clean rejection
 * (return < 0) with no out-of-bounds read (caught by the ASan job). The
 * sticky-error reader in wn_msg latches r.err on any over-read, which the
 * parser surfaces as WOLFNANO_E_INVALID_ARG. Complements serverhello_test.c.
 */

#include "wn_serverhello.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

/* RFC 8448 section 3 ServerHello: the valid baseline we mutate. Ext-block
 * length (U16) sits at offset 42; key_share group x25519 at the first ext. */
static const byte shGood[] = {
    0x02,0x00,0x00,0x56,0x03,0x03,0xa6,0xaf,0x06,0xa4,0x12,0x18,0x60,0xdc,0x5e,0x6e,
    0x60,0x24,0x9c,0xd3,0x4c,0x95,0x93,0x0c,0x8a,0xc5,0xcb,0x14,0x34,0xda,0xc1,0x55,
    0x77,0x2e,0xd3,0xe2,0x69,0x28,0x00,0x13,0x01,0x00,0x00,0x2e,0x00,0x33,0x00,0x24,
    0x00,0x1d,0x00,0x20,0xc9,0x82,0x88,0x76,0x11,0x20,0x95,0xfe,0x66,0x76,0x2b,0xdb,
    0xf7,0xc6,0x72,0xe1,0x56,0xd6,0xcc,0x25,0x3b,0x83,0x3d,0xf1,0xdd,0x69,0xb1,0xb0,
    0x4e,0x75,0x1f,0x0f,0x00,0x2b,0x00,0x02,0x03,0x04
};

int main(void)
{
    byte buf[256];
    wn_ServerHello s;
    word32 n = (word32)sizeof(shGood);
    int rc;

    printf("wolfNano ServerHello negative-input test\n");

    rc = wn_ServerHello_Parse(shGood, n, &s);
    check(rc == WOLFNANO_SUCCESS, "baseline valid ServerHello parses");

    check(wn_ServerHello_Parse(NULL, n, &s) < 0, "reject NULL msg");
    check(wn_ServerHello_Parse(shGood, n, NULL) < 0, "reject NULL out");

    check(wn_ServerHello_Parse(shGood, 0, &s) < 0, "reject zero length");
    check(wn_ServerHello_Parse(shGood, 4, &s) < 0, "reject header-only (no random)");
    check(wn_ServerHello_Parse(shGood, 10, &s) < 0, "reject truncated in random");
    check(wn_ServerHello_Parse(shGood, 41, &s) < 0, "reject truncated before extensions");

    memset(buf, 0, sizeof(buf));
    memcpy(buf, shGood, n);
    buf[0] = 0x01;                              /* ClientHello, not ServerHello */
    check(wn_ServerHello_Parse(buf, n, &s) < 0, "reject wrong handshake type");

    memset(buf, 0, sizeof(buf));
    memcpy(buf, shGood, n);
    buf[3] ^= 0xFF;                             /* corrupt 24-bit hsLen */
    check(wn_ServerHello_Parse(buf, n, &s) < 0, "reject hsLen != msgLen-4");

    memset(buf, 0, sizeof(buf));
    memcpy(buf, shGood, n);
    check(wn_ServerHello_Parse(buf, n + 20, &s) < 0, "reject overlong msgLen");

    memset(buf, 0, sizeof(buf));
    memcpy(buf, shGood, n);
    buf[42] = 0xFF; buf[43] = 0xFF;            /* ext-block length far too large */
    check(wn_ServerHello_Parse(buf, n, &s) < 0, "reject overlong extensions length");

    memset(buf, 0, sizeof(buf));
    memcpy(buf, shGood, n);
    buf[38] = 0xFF;                             /* legacy_session_id_echo len = 255 */
    check(wn_ServerHello_Parse(buf, n, &s) < 0, "reject overlong session_id echo");

    memset(buf, 0, sizeof(buf));
    memcpy(buf, shGood, n);
    buf[46] = 0xFF; buf[47] = 0xFF;            /* first extension body overruns block */
    check(wn_ServerHello_Parse(buf, n, &s) < 0,
          "reject extension body overrunning block");

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
