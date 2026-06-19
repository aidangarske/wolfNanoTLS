/* rfc8448_test.c
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
 * RFC 8448 section 3 record-key KATs: HKDF-Expand-Label of each traffic secret
 * into the "key"/"iv" the record layer uses. keyschedule_test.c covers the
 * secret derivations and the server handshake key/iv; this completes the set
 * with the client handshake keys and both application-data keys, so all four
 * (client/server x handshake/application) write keys are vector-checked.
 */

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
    /* Traffic secrets from RFC 8448 section 3 (also KAT'd in keyschedule_test). */
    static const byte cHsTraffic[32] = {
        0xb3,0xed,0xdb,0x12,0x6e,0x06,0x7f,0x35,0xa7,0x80,0xb3,0xab,0xf4,0x5e,0x2d,0x8f,
        0x3b,0x1a,0x95,0x07,0x38,0xf5,0x2e,0x96,0x00,0x74,0x6a,0x0e,0x27,0xa5,0x5a,0x21
    };
    static const byte sHsTraffic[32] = {
        0xb6,0x7b,0x7d,0x69,0x0c,0xc1,0x6c,0x4e,0x75,0xe5,0x42,0x13,0xcb,0x2d,0x37,0xb4,
        0xe9,0xc9,0x12,0xbc,0xde,0xd9,0x10,0x5d,0x42,0xbe,0xfd,0x59,0xd3,0x91,0xad,0x38
    };
    static const byte cApTraffic[32] = {
        0x9e,0x40,0x64,0x6c,0xe7,0x9a,0x7f,0x9d,0xc0,0x5a,0xf8,0x88,0x9b,0xce,0x65,0x52,
        0x87,0x5a,0xfa,0x0b,0x06,0xdf,0x00,0x87,0xf7,0x92,0xeb,0xb7,0xc1,0x75,0x04,0xa5
    };
    static const byte sApTraffic[32] = {
        0xa1,0x1a,0xf9,0xf0,0x55,0x31,0xf8,0x56,0xad,0x47,0x11,0x6b,0x45,0xa9,0x50,0x32,
        0x82,0x04,0xb4,0xf4,0x4b,0xfb,0x6b,0x3a,0x4b,0x4f,0x1f,0x3f,0xcb,0x63,0x16,0x43
    };

    /* Expected record keys/IVs (RFC 8448 section 3). */
    static const byte cHsKey[16] = {
        0xdb,0xfa,0xa6,0x93,0xd1,0x76,0x2c,0x5b,0x66,0x6a,0xf5,0xd9,0x50,0x25,0x8d,0x01
    };
    static const byte cHsIv[12] = {
        0x5b,0xd3,0xc7,0x1b,0x83,0x6e,0x0b,0x76,0xbb,0x73,0x26,0x5f
    };
    static const byte sApKey[16] = {
        0x9f,0x02,0x28,0x3b,0x6c,0x9c,0x07,0xef,0xc2,0x6b,0xb9,0xf2,0xac,0x92,0xe3,0x56
    };
    static const byte sApIv[12] = {
        0xcf,0x78,0x2b,0x88,0xdd,0x83,0x54,0x9a,0xad,0xf1,0xe9,0x84
    };
    static const byte cApKey[16] = {
        0x17,0x42,0x2d,0xda,0x59,0x6e,0xd5,0xd9,0xac,0xd8,0x90,0xe3,0xc6,0x3f,0x50,0x51
    };
    static const byte cApIv[12] = {
        0x5b,0x78,0x92,0x3d,0xee,0x08,0x57,0x90,0x33,0xe5,0x23,0xd9
    };

    byte key[16];
    byte iv[12];
    int rc;

    printf("wolfNanoTLS RFC 8448 section 3 record-key KATs\n");

    rc = wn_Tls13_ExpandLabel(key, sizeof(key), cHsTraffic, "key", NULL, 0,
                              WC_SHA256);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(key, cHsKey, 16),
          "client handshake write key");
    rc = wn_Tls13_ExpandLabel(iv, sizeof(iv), cHsTraffic, "iv", NULL, 0,
                              WC_SHA256);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(iv, cHsIv, 12),
          "client handshake write iv");

    rc = wn_Tls13_ExpandLabel(key, sizeof(key), sApTraffic, "key", NULL, 0,
                              WC_SHA256);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(key, sApKey, 16),
          "server application write key");
    rc = wn_Tls13_ExpandLabel(iv, sizeof(iv), sApTraffic, "iv", NULL, 0,
                              WC_SHA256);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(iv, sApIv, 12),
          "server application write iv");

    rc = wn_Tls13_ExpandLabel(key, sizeof(key), cApTraffic, "key", NULL, 0,
                              WC_SHA256);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(key, cApKey, 16),
          "client application write key");
    rc = wn_Tls13_ExpandLabel(iv, sizeof(iv), cApTraffic, "iv", NULL, 0,
                              WC_SHA256);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(iv, cApIv, 12),
          "client application write iv");

    (void)sHsTraffic;   /* server handshake key/iv KAT'd in keyschedule_test */

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
