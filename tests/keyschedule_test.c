/* keyschedule_test.c
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

/* TLS 1.3 key-schedule KATs from RFC 8448 section 3 (SHA-256). */

#include "wolfnano_crypto.h"
#include "wn_keyschedule.h"
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
    }
}

static int eq(const byte* a, const byte* b, word32 n)
{
    return XMEMCMP(a, b, n) == 0;
}

int main(void)
{
    /* RFC 8448 section 3 */
    static const byte earlyExp[32] = {
        0x33,0xad,0x0a,0x1c,0x60,0x7e,0xc0,0x3b,0x09,0xe6,0xcd,0x98,0x93,0x68,0x0c,0xe2,
        0x10,0xad,0xf3,0x00,0xaa,0x1f,0x26,0x60,0xe1,0xb2,0x2e,0x10,0xf1,0x70,0xf9,0x2a
    };
    static const byte emptyHashExp[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    static const byte derivedExp[32] = {
        0x6f,0x26,0x15,0xa1,0x08,0xc7,0x02,0xc5,0x67,0x8f,0x54,0xfc,0x9d,0xba,0xb6,0x97,
        0x16,0xc0,0x76,0x18,0x9c,0x48,0x25,0x0c,0xeb,0xea,0xc3,0x57,0x6c,0x36,0x11,0xba
    };
    byte psk[32];
    byte early[32];
    byte emptyHash[32];
    byte derived[32];
    int rc;

    printf("wolfNanoTLS TLS 1.3 key-schedule KATs (RFC 8448 section 3)\n");

    XMEMSET(psk, 0, sizeof(psk));

    rc = wn_Tls13_Extract(early, NULL, 0, psk, sizeof(psk), WC_SHA256);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(early, earlyExp, 32),
          "Early Secret = HKDF-Extract(0, 0)");

    rc = wc_Sha256Hash((const byte*)"", 0, emptyHash);
    check((rc == 0) && eq(emptyHash, emptyHashExp, 32),
          "Transcript-Hash(\"\") = SHA-256(\"\")");

    rc = wn_Tls13_DeriveSecret(derived, early, "derived", emptyHash, 32,
                               WC_SHA256);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(derived, derivedExp, 32),
          "Derive-Secret(Early, \"derived\", \"\")");

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
