/* serverhello_test.c
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

/* ServerHello parser test against the RFC 8448 section 3 ServerHello bytes. */

#include "wn_serverhello.h"
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
    /* RFC 8448 section 3: server ServerHello handshake message */
    static const byte sh[] = {
        0x02,0x00,0x00,0x56,0x03,0x03,0xa6,0xaf,0x06,0xa4,0x12,0x18,0x60,0xdc,0x5e,0x6e,
        0x60,0x24,0x9c,0xd3,0x4c,0x95,0x93,0x0c,0x8a,0xc5,0xcb,0x14,0x34,0xda,0xc1,0x55,
        0x77,0x2e,0xd3,0xe2,0x69,0x28,0x00,0x13,0x01,0x00,0x00,0x2e,0x00,0x33,0x00,0x24,
        0x00,0x1d,0x00,0x20,0xc9,0x82,0x88,0x76,0x11,0x20,0x95,0xfe,0x66,0x76,0x2b,0xdb,
        0xf7,0xc6,0x72,0xe1,0x56,0xd6,0xcc,0x25,0x3b,0x83,0x3d,0xf1,0xdd,0x69,0xb1,0xb0,
        0x4e,0x75,0x1f,0x0f,0x00,0x2b,0x00,0x02,0x03,0x04
    };
    static const byte expectKey[32] = {
        0xc9,0x82,0x88,0x76,0x11,0x20,0x95,0xfe,0x66,0x76,0x2b,0xdb,0xf7,0xc6,0x72,0xe1,
        0x56,0xd6,0xcc,0x25,0x3b,0x83,0x3d,0xf1,0xdd,0x69,0xb1,0xb0,0x4e,0x75,0x1f,0x0f
    };
    wn_ServerHello s;
    int rc;

    printf("wolfNano ServerHello parser test (RFC 8448 section 3)\n");

    rc = wn_ServerHello_Parse(sh, (word32)sizeof(sh), &s);
    check(rc == WOLFNANO_SUCCESS, "parse ServerHello");
    check(s.cipher == 0x1301, "negotiated cipher TLS_AES_128_GCM_SHA256");
    check(s.version == 0x0304, "selected version TLS 1.3");
    check(s.group == 0x001d, "key_share group x25519");
    check((s.keyShareLen == 32) && (s.keyShare != NULL) &&
          (XMEMCMP(s.keyShare, expectKey, 32) == 0),
          "server key_share extracted correctly");

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
