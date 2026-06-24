/* mldsa_test.c
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

/* ML-DSA sign/verify round-trip and tamper rejection (level via WOLFNANO_MLDSA_LEVEL). */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

#if WOLFNANO_MLDSA_LEVEL == 2
    #define WN_T_MLDSA_PARAM WC_ML_DSA_44
    #define WN_T_MLDSA_NAME  "ML-DSA-44"
#elif WOLFNANO_MLDSA_LEVEL == 3
    #define WN_T_MLDSA_PARAM WC_ML_DSA_65
    #define WN_T_MLDSA_NAME  "ML-DSA-65"
#else
    #define WN_T_MLDSA_PARAM WC_ML_DSA_87
    #define WN_T_MLDSA_NAME  "ML-DSA-87"
#endif

int main(void)
{
    WC_RNG rng;
    wc_MlDsaKey key;
    byte sig[5000];
    const byte msg[12] = { 'w','o','l','f','N','a','n','o',' ','p','q','c' };
    word32 sigLen;
    int sigSz = 0, res = 0, rc;

    printf("wolfNano " WN_T_MLDSA_NAME " sign/verify test\n");

    rc = wc_InitRng(&rng);
    check(rc == 0, "RNG init");

    rc  = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    rc |= wc_MlDsaKey_SetParams(&key, WN_T_MLDSA_PARAM);
    rc |= wc_MlDsaKey_MakeKey(&key, &rng);
    rc |= wc_MlDsaKey_GetSigLen(&key, &sigSz);
    check((rc == 0) && (sigSz > 0) && (sigSz <= (int)sizeof(sig)),
          "keygen + signature size");

    sigLen = (word32)sizeof(sig);
    rc = wc_MlDsaKey_SignCtx(&key, NULL, 0, sig, &sigLen, msg, sizeof(msg),
                             &rng);
    check((rc == 0) && (sigLen == (word32)sigSz), "sign");

    res = 0;
    rc = wc_MlDsaKey_VerifyCtx(&key, sig, sigLen, NULL, 0, msg, sizeof(msg),
                               &res);
    check((rc == 0) && (res == 1), "verify");

    sig[0] ^= 0x01;
    res = 1;
    rc = wc_MlDsaKey_VerifyCtx(&key, sig, sigLen, NULL, 0, msg, sizeof(msg),
                               &res);
    check(res != 1, "tampered signature rejected");

    wc_MlDsaKey_Free(&key);
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
