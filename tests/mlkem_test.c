/* mlkem_test.c
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

/* ML-KEM-768 KEM round-trip: encapsulate/decapsulate shared secrets agree. */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
    }
}

int main(void)
{
    WC_RNG rng;
    MlKemKey srv, cli;
    byte pub[WC_ML_KEM_768_PUBLIC_KEY_SIZE];
    byte ct[WC_ML_KEM_768_CIPHER_TEXT_SIZE];
    byte ssC[WC_ML_KEM_SS_SZ], ssS[WC_ML_KEM_SS_SZ];
    word32 pubLen = 0, ctLen = 0;
    int rc;

    printf("wolfNanoTLS ML-KEM-768 KEM test\n");

    rc = wc_InitRng(&rng);
    check(rc == 0, "RNG init");

    rc  = wc_MlKemKey_Init(&srv, WC_ML_KEM_768, NULL, INVALID_DEVID);
    rc |= wc_MlKemKey_MakeKey(&srv, &rng);
    rc |= wc_MlKemKey_PublicKeySize(&srv, &pubLen);
    rc |= wc_MlKemKey_EncodePublicKey(&srv, pub, pubLen);
    check((rc == 0) && (pubLen == WC_ML_KEM_768_PUBLIC_KEY_SIZE),
          "server keygen + export public key");

    rc  = wc_MlKemKey_Init(&cli, WC_ML_KEM_768, NULL, INVALID_DEVID);
    rc |= wc_MlKemKey_DecodePublicKey(&cli, pub, pubLen);
    rc |= wc_MlKemKey_CipherTextSize(&cli, &ctLen);
    rc |= wc_MlKemKey_Encapsulate(&cli, ct, ssC, &rng);
    check((rc == 0) && (ctLen == WC_ML_KEM_768_CIPHER_TEXT_SIZE),
          "client encapsulate");

    rc = wc_MlKemKey_Decapsulate(&srv, ssS, ct, ctLen);
    check((rc == 0) && (XMEMCMP(ssC, ssS, WC_ML_KEM_SS_SZ) == 0),
          "shared secrets agree");

    wc_MlKemKey_Free(&srv);
    wc_MlKemKey_Free(&cli);
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
