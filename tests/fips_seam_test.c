/* fips_seam_test.c
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

/* Provider-seam proof for WOLFNANO_CRYPTO=fips. Exercises the FIPS-boundary
 * crypto the handshake uses, entirely through the wc_* seam header, and asserts
 * the in-core integrity / power-on self-tests passed. */

#include "wolfnano_crypto.h"
#include <wolfssl/wolfcrypt/fips_test.h>
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

/* On an in-core integrity mismatch the module hands back the hash computed for
 * THIS linked binary; the build harness patches it into fips_test.c and relinks
 * so the check passes (the standard per-artifact FIPS integration step). */
static void fipsCb(int ok, int err, const char* hash)
{
    if (!ok) {
        printf("FIPS_INCORE_HASH=%s\n", hash);
        (void)err;
    }
}

int main(void)
{
    static const byte abc[3] = { 0x61, 0x62, 0x63 };
    static const byte sha256Abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    byte digest[32];
    byte prk[32];
    byte okm[16];
    byte ct[32];
    byte pt[32];
    byte tag[16];
    byte plain[16];
    byte key[16];
    byte iv[12];
    Aes aes;
    int ret;

    XMEMSET(key, 0x2b, sizeof(key));
    XMEMSET(iv, 0x00, sizeof(iv));
    XMEMSET(plain, 0x41, sizeof(plain));

    wolfCrypt_SetCb_fips(fipsCb);
    ret = wc_Sha256Hash(abc, (word32)sizeof(abc), digest);
    if (wolfCrypt_GetStatus_fips() == -203) {
        return 2;  /* in-core hash not yet set for this binary; harness patches */
    }

    check(wolfCrypt_GetStatus_fips() == 0, "FIPS in-core integrity / CAST status");

    ret = wc_Sha256Hash(abc, (word32)sizeof(abc), digest);
    check((ret == 0) && (XMEMCMP(digest, sha256Abc, 32) == 0),
          "wc_Sha256Hash KAT through seam");

    /* FIPS gates TLS key derivation behind the private-key-read service
     * indicator; wolfSSL's tls13.c toggles it the same way under HAVE_FIPS. */
    wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);

    XMEMSET(digest, 0, sizeof(digest));
    ret = wc_Tls13_HKDF_Extract(prk, NULL, 0, digest, 32, WC_SHA256);
    check(ret == 0, "wc_Tls13_HKDF_Extract through seam");

    ret = wc_Tls13_HKDF_Expand_Label(okm, (word32)sizeof(okm), prk, 32,
                                     (const byte*)"tls13 ", 6,
                                     (const byte*)"key", 3, NULL, 0, WC_SHA256);
    check(ret == 0, "wc_Tls13_HKDF_Expand_Label through seam");

    wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, (word32)sizeof(key));
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, ct, plain, (word32)sizeof(plain),
                               iv, (word32)sizeof(iv), tag, (word32)sizeof(tag),
                               NULL, 0);
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, pt, ct, (word32)sizeof(plain),
                               iv, (word32)sizeof(iv), tag, (word32)sizeof(tag),
                               NULL, 0);
    }
    wc_AesFree(&aes);
    check((ret == 0) && (XMEMCMP(pt, plain, sizeof(plain)) == 0),
          "wc_AesGcm round trip through seam");

    if (fails == 0) {
        printf("ALL PASS fips seam (wolfCrypt FIPS backend)\n");
    }
    return fails == 0 ? 0 : 1;
}
