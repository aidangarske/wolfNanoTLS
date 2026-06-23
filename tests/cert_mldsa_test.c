/* cert_mldsa_test.c
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

/* ML-DSA-65 TLS 1.3 CertificateVerify (SignatureScheme 0x0905): keygen + sign
 * a CertificateVerify TBS, export the public key to SPKI DER, then drive the
 * client's wn_CertVerify path and assert accept (good sig) + reject (tampered).
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>

#include "../src/wn_connect.c"

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
    WC_RNG rng;
    wc_MlDsaKey key;
    byte th[32];
    byte tbs[64 + 33 + 1 + 32];
    byte spki[2048];
    byte sig[5000];
    word32 tbsLen = 0;
    word32 sigLen;
    int spkiLen, rc, verifyRc;
    word32 i;

    printf("wolfNanoTLS ML-DSA-65 CertificateVerify test (scheme 0x0905)\n");

    for (i = 0; i < sizeof(th); i++) {
        th[i] = (byte)i;
    }
    wn_BuildCvTbs(tbs, &tbsLen, th, sizeof(th));

    rc = wc_InitRng(&rng);
    check(rc == 0, "RNG init");

    rc  = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    rc |= wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65);
    rc |= wc_MlDsaKey_MakeKey(&key, &rng);
    check(rc == 0, "ML-DSA-65 keygen");

    spkiLen = wc_MlDsaKey_PublicKeyToDer(&key, spki, (word32)sizeof(spki), 1);
    check(spkiLen > 0, "export public key to SPKI DER");

    sigLen = (word32)sizeof(sig);
    rc = wc_MlDsaKey_SignCtx(&key, NULL, 0, sig, &sigLen, tbs, tbsLen, &rng);
    check(rc == 0, "sign CertificateVerify TBS");

    verifyRc = wn_CertVerify(0x0905, spki, (word32)spkiLen, th, sizeof(th),
                             sig, sigLen);
    check(verifyRc == WOLFNANOTLS_SUCCESS, "CertificateVerify accepted (0x0905)");

    sig[0] ^= 0x01;
    verifyRc = wn_CertVerify(0x0905, spki, (word32)spkiLen, th, sizeof(th),
                             sig, sigLen);
    check(verifyRc != WOLFNANOTLS_SUCCESS, "tampered signature rejected");

    wc_MlDsaKey_Free(&key);
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
