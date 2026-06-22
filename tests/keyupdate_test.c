/* keyupdate_test.c
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
 * KAT for the post-handshake key update (RFC 8446 4.6.3 / 7.2): pins the
 * "traffic upd" secret derivation and the re-derived AES-128-GCM key/iv so a
 * regression in wn_Tls13_KeyUpdate (label, order, sizes) fails loudly.
 */

#include "wn_keyschedule.h"
#include <wolfssl/wolfcrypt/hash.h>
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

/* Input secret: 32 bytes of 0x01. Expected outputs computed from
 * wn_Tls13_KeyUpdate over SHA-256 (whose HKDF path is RFC 8448 KAT-verified
 * in keyschedule_test). */
static const byte inSecret[32] = {
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01
};
static const byte expSecret[32] = {
    0x22,0xcf,0xf2,0x5f,0xf3,0xdf,0x5a,0x42,0xc5,0x57,0x73,0x24,0x56,0x75,0x4d,
    0x4f,0x80,0x37,0x2a,0xd4,0xd6,0x07,0x1f,0x71,0xf4,0xe2,0x4d,0x00,0x1f,0x66,
    0xb0,0x73
};
static const byte expKey[16] = {
    0xed,0x36,0xc5,0xc8,0x3a,0x71,0x22,0xb7,0x0a,0x84,0xf4,0xc6,0x45,0xa0,0x08,
    0xfe
};
static const byte expIv[12] = {
    0xb7,0xe8,0xf2,0x40,0x33,0x23,0xa9,0x56,0xe8,0x68,0x3c,0x64
};

int main(void)
{
    byte secret[32];
    byte key[16];
    byte iv[12];
    int ret;

    XMEMCPY(secret, inSecret, sizeof(secret));
    ret = wn_Tls13_KeyUpdate(secret, key, iv, WC_SHA256);

    check(ret == 0, "wn_Tls13_KeyUpdate returns success");
    check(XMEMCMP(secret, expSecret, sizeof(secret)) == 0,
          "updated secret matches KAT (traffic upd)");
    check(XMEMCMP(key, expKey, sizeof(key)) == 0, "re-derived key matches KAT");
    check(XMEMCMP(iv, expIv, sizeof(iv)) == 0, "re-derived iv matches KAT");
    check(XMEMCMP(secret, inSecret, sizeof(secret)) != 0,
          "updated secret differs from input");

    check(wn_Tls13_KeyUpdate(NULL, key, iv, WC_SHA256) != 0,
          "NULL secret rejected");

    if (fails == 0) {
        printf("keyupdate_test: all checks passed\n");
    }
    else {
        printf("keyupdate_test: %d FAILED\n", fails);
    }

    return fails == 0 ? 0 : 1;
}
