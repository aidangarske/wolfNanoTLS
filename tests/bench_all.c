/* bench_all.c
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

/* All-algo crypto speed bench over the wc_* seam. Build for one arch via the
 * Makefile (WOLFNANOTLS_ASM=<arch>); each algo is gated by its enable macro and
 * prints n/a when off. Run the none and intel builds to compare C vs asm. */

#include "wolfnano_crypto.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/sha3.h>
#ifdef HAVE_CHACHA
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#if !defined(NO_RSA)
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef WOLFSSL_HAVE_MLKEM
    #include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#include <stdio.h>
#include <time.h>

#ifndef BUF_SZ
    #define BUF_SZ 16384
#endif
#define RUNSEC 0.3

static byte buf[BUF_SZ];
static byte obuf[BUF_SZ + 64];

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Time op() for ~RUNSEC, reporting MB/s over nbytes per call. op returns 0 ok. */
#define BENCH_BYTES(label, nbytes, op) do {                                  \
        double _t0 = now_sec(), _el;                                         \
        unsigned long _n = 0; int _r = 0;                                    \
        do { _r = (op); _n++; } while ((now_sec() - _t0) < RUNSEC);          \
        _el = now_sec() - _t0;                                               \
        if (_r == 0) printf("  %-26s %12.1f MB/s\n", label,                  \
            ((double)_n * (nbytes)) / (1024.0 * 1024.0) / _el);              \
        else printf("  %-26s   FAIL (%d)\n", label, _r);                     \
    } while (0)

/* Time op() for ~RUNSEC, reporting ops/s. op returns 0 ok. */
#define BENCH_OPS(label, op) do {                                            \
        double _t0 = now_sec(), _el;                                         \
        unsigned long _n = 0; int _r = 0;                                    \
        do { _r = (op); _n++; } while ((now_sec() - _t0) < RUNSEC);          \
        _el = now_sec() - _t0;                                               \
        if (_r == 0) printf("  %-26s %12.1f ops/s\n", label, _n / _el);      \
        else printf("  %-26s   FAIL (%d)\n", label, _r);                     \
    } while (0)

#define NA(label) printf("  %-26s          n/a\n", label)

static void banner(void)
{
    printf("wolfNanoTLS bench [");
#if defined(WOLFSSL_AESNI) || defined(WOLFSSL_ARMASM) || defined(WOLFSSL_RISCV_ASM)
    #ifdef WOLFSSL_AESNI
        printf("AES-NI ");
    #endif
    #ifdef HAVE_INTEL_AVX2
        printf("AVX2 ");
    #elif defined(HAVE_INTEL_AVX1)
        printf("AVX1 ");
    #endif
    #ifdef WOLFSSL_SP_X86_64_ASM
        printf("SP-x86_64-asm ");
    #endif
    #ifdef WOLFSSL_SP_ARM_CORTEX_M_ASM
        printf("SP-cortexm-asm ");
    #endif
    #ifdef WOLFSSL_ARMASM
        printf("ARMASM ");
    #endif
    #ifdef WOLFSSL_RISCV_ASM
        printf("RISCV-asm ");
    #endif
#else
    printf("PORTABLE_C, no asm");
#endif
    printf("]\n");
}

static void bench_hashes(void)
{
    byte d[64];

    printf("-- hash / mac --\n");
    BENCH_BYTES("SHA-256", BUF_SZ, wc_Sha256Hash(buf, BUF_SZ, d));
#ifdef WOLFSSL_SHA384
    BENCH_BYTES("SHA-384", BUF_SZ, wc_Sha384Hash(buf, BUF_SZ, d));
#else
    NA("SHA-384");
#endif
#ifdef WOLFSSL_SHA3
    BENCH_BYTES("SHA3-256", BUF_SZ, wc_Sha3_256Hash(buf, BUF_SZ, d));
#else
    NA("SHA3-256");
#endif
}

static void bench_hmac(void)
{
    Hmac h;
    byte key[32], out[32];
    int ok;

    XMEMSET(key, 0x0b, sizeof(key));
    ok = (wc_HmacInit(&h, NULL, INVALID_DEVID) == 0) &&
         (wc_HmacSetKey(&h, WC_SHA256, key, sizeof(key)) == 0);
    if (ok) {
        BENCH_BYTES("HMAC-SHA256", BUF_SZ,
            (wc_HmacUpdate(&h, buf, BUF_SZ) || wc_HmacFinal(&h, out)));
        wc_HmacFree(&h);
    }
    else {
        NA("HMAC-SHA256");
    }
}

static void bench_aead(void)
{
    Aes aes;
    byte key[32], iv[12], tag[16];

    XMEMSET(key, 0x2b, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));

    printf("-- aead --\n");
#ifdef HAVE_AESGCM
    if ((wc_AesInit(&aes, NULL, INVALID_DEVID) == 0) &&
        (wc_AesGcmSetKey(&aes, key, 16) == 0)) {
        BENCH_BYTES("AES-128-GCM enc", BUF_SZ,
            wc_AesGcmEncrypt(&aes, obuf, buf, BUF_SZ, iv, 12, tag, 16, NULL, 0));
        wc_AesFree(&aes);
    }
    if ((wc_AesInit(&aes, NULL, INVALID_DEVID) == 0) &&
        (wc_AesGcmSetKey(&aes, key, 32) == 0)) {
        BENCH_BYTES("AES-256-GCM enc", BUF_SZ,
            wc_AesGcmEncrypt(&aes, obuf, buf, BUF_SZ, iv, 12, tag, 16, NULL, 0));
        wc_AesFree(&aes);
    }
#else
    NA("AES-128-GCM enc");
    NA("AES-256-GCM enc");
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    BENCH_BYTES("ChaCha20-Poly1305 enc", BUF_SZ,
        wc_ChaCha20Poly1305_Encrypt(key, iv, NULL, 0, buf, BUF_SZ, obuf,
                                    obuf + BUF_SZ));
#else
    NA("ChaCha20-Poly1305 enc");
#endif
}

#ifdef HAVE_ECC
static void bench_ecc(WC_RNG* rng)
{
    ecc_key k256, k384;
    byte hash[32], sig[80];
    byte sec[48];
    word32 sigLen, secLen;
    int ok, res;

    printf("-- ecc --\n");
    XMEMSET(hash, 0x5a, sizeof(hash));
    ok = (wc_ecc_init(&k256) == 0) &&
         (wc_ecc_make_key_ex(rng, 32, &k256, ECC_SECP256R1) == 0) &&
         (wc_ecc_set_rng(&k256, rng) == 0);
    if (ok) {
        BENCH_OPS("ECDSA P-256 sign",
            (sigLen = sizeof(sig),
             wc_ecc_sign_hash(hash, 32, sig, &sigLen, rng, &k256)));
        sigLen = sizeof(sig);
        if (wc_ecc_sign_hash(hash, 32, sig, &sigLen, rng, &k256) == 0) {
            BENCH_OPS("ECDSA P-256 verify",
                wc_ecc_verify_hash(sig, sigLen, hash, 32, &res, &k256));
        }
        BENCH_OPS("ECDH P-256",
            (secLen = sizeof(sec),
             wc_ecc_shared_secret(&k256, &k256, sec, &secLen)));
        wc_ecc_free(&k256);
    }
    else {
        NA("ECDSA P-256 sign");
    }
#ifdef HAVE_ECC384
    if ((wc_ecc_init(&k384) == 0) &&
        (wc_ecc_make_key_ex(rng, 48, &k384, ECC_SECP384R1) == 0) &&
        (wc_ecc_set_rng(&k384, rng) == 0)) {
        BENCH_OPS("ECDH P-384",
            (secLen = sizeof(sec),
             wc_ecc_shared_secret(&k384, &k384, sec, &secLen)));
        wc_ecc_free(&k384);
    }
    else {
        NA("ECDH P-384");
    }
#else
    NA("ECDH P-384");
#endif
}
#endif /* HAVE_ECC */

static void bench_25519(WC_RNG* rng)
{
#ifdef HAVE_ED25519
    ed25519_key ek;
    byte emsg[32], esig[64];
    word32 esigLen;
    int eres;
#endif
#ifdef HAVE_CURVE25519
    curve25519_key ck;
    byte csec[32];
    word32 csecLen;
#endif

#if defined(HAVE_ED25519) || defined(HAVE_CURVE25519)
    printf("-- 25519 --\n");
#endif
#ifdef HAVE_ED25519
    XMEMSET(emsg, 0x5a, sizeof(emsg));
    if ((wc_ed25519_init(&ek) == 0) &&
        (wc_ed25519_make_key(rng, 32, &ek) == 0)) {
        BENCH_OPS("Ed25519 sign",
            (esigLen = sizeof(esig),
             wc_ed25519_sign_msg(emsg, sizeof(emsg), esig, &esigLen, &ek)));
        esigLen = sizeof(esig);
        if (wc_ed25519_sign_msg(emsg, sizeof(emsg), esig, &esigLen, &ek) == 0) {
            BENCH_OPS("Ed25519 verify",
                wc_ed25519_verify_msg(esig, esigLen, emsg, sizeof(emsg), &eres,
                                      &ek));
        }
        wc_ed25519_free(&ek);
    }
#endif
#ifdef HAVE_CURVE25519
    if ((wc_curve25519_init(&ck) == 0) &&
        (wc_curve25519_make_key(rng, 32, &ck) == 0)) {
        BENCH_OPS("X25519",
            (csecLen = sizeof(csec),
             wc_curve25519_shared_secret(&ck, &ck, csec, &csecLen)));
        wc_curve25519_free(&ck);
    }
#endif
}

static void bench_rsa(WC_RNG* rng)
{
#if !defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
    RsaKey k;
    byte in[32], sig[256], out[256];
    word32 sigLen, outLen;
    int ok;
#endif

    printf("-- rsa --\n");
#if !defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
    XMEMSET(in, 0x5a, sizeof(in));
    ok = (wc_InitRsaKey(&k, NULL) == 0) &&
         (wc_MakeRsaKey(&k, 2048, 65537, rng) == 0);
    if (ok) {
        sigLen = sizeof(sig);
        if (wc_RsaSSL_Sign(in, sizeof(in), sig, sigLen, &k, rng) >= 0) {
            BENCH_OPS("RSA-2048 sign (priv)",
                (sigLen = sizeof(sig),
                 (wc_RsaSSL_Sign(in, sizeof(in), sig, sigLen, &k, rng) < 0)));
            sigLen = (word32)wc_RsaSSL_Sign(in, sizeof(in), sig, sizeof(sig),
                                            &k, rng);
            BENCH_OPS("RSA-2048 verify (pub)",
                (outLen = sizeof(out),
                 (wc_RsaSSL_Verify(sig, sigLen, out, outLen, &k) < 0)));
        }
        wc_FreeRsaKey(&k);
    }
    else {
        NA("RSA-2048 sign (priv)");
    }
#else
    NA("RSA-2048 sign (priv)");
    NA("RSA-2048 verify (pub)");
#endif
}

static void bench_pqc(WC_RNG* rng)
{
#ifdef WOLFSSL_HAVE_MLKEM
    MlKemKey kk;
    byte ct[WC_ML_KEM_768_CIPHER_TEXT_SIZE];
    byte ss[WC_ML_KEM_SS_SZ], ss2[WC_ML_KEM_SS_SZ];
    word32 ctLen;
    int kok;
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    MlDsaKey dk;
    byte dmsg[32];
    byte dsig[5000];
    word32 dsigLen;
    int dok, dres;
#endif

#if defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_HAVE_MLDSA)
    printf("-- pqc --\n");
#endif
#ifdef WOLFSSL_HAVE_MLKEM
    kok = (wc_MlKemKey_Init(&kk, WC_ML_KEM_768, NULL, INVALID_DEVID) == 0) &&
          (wc_MlKemKey_MakeKey(&kk, rng) == 0) &&
          (wc_MlKemKey_CipherTextSize(&kk, &ctLen) == 0);
    if (kok) {
        BENCH_OPS("ML-KEM-768 keygen", wc_MlKemKey_MakeKey(&kk, rng));
        BENCH_OPS("ML-KEM-768 encap", wc_MlKemKey_Encapsulate(&kk, ct, ss, rng));
        if (wc_MlKemKey_Encapsulate(&kk, ct, ss, rng) == 0) {
            BENCH_OPS("ML-KEM-768 decap",
                wc_MlKemKey_Decapsulate(&kk, ss2, ct, ctLen));
        }
        wc_MlKemKey_Free(&kk);
    }
#else
    NA("ML-KEM-768 keygen");
#endif
#ifdef WOLFSSL_HAVE_MLDSA
  #if WOLFNANOTLS_MLDSA_LEVEL == 2
    #define WN_B_MLDSA_PARAM WC_ML_DSA_44
  #elif WOLFNANOTLS_MLDSA_LEVEL == 3
    #define WN_B_MLDSA_PARAM WC_ML_DSA_65
  #else
    #define WN_B_MLDSA_PARAM WC_ML_DSA_87
  #endif
    XMEMSET(dmsg, 0x5a, sizeof(dmsg));
    dok = (wc_MlDsaKey_Init(&dk, NULL, INVALID_DEVID) == 0) &&
          (wc_MlDsaKey_SetParams(&dk, WN_B_MLDSA_PARAM) == 0);
  #ifndef WOLFSSL_MLDSA_VERIFY_ONLY
    if (dok && (wc_MlDsaKey_MakeKey(&dk, rng) == 0)) {
        BENCH_OPS("ML-DSA sign",
            (dsigLen = sizeof(dsig),
             wc_MlDsaKey_SignCtx(&dk, NULL, 0, dsig, &dsigLen, dmsg,
                                 sizeof(dmsg), rng)));
        dsigLen = sizeof(dsig);
        if (wc_MlDsaKey_SignCtx(&dk, NULL, 0, dsig, &dsigLen, dmsg,
                                sizeof(dmsg), rng) == 0) {
            BENCH_OPS("ML-DSA verify",
                wc_MlDsaKey_VerifyCtx(&dk, dsig, dsigLen, NULL, 0, dmsg,
                                      sizeof(dmsg), &dres));
        }
        wc_MlDsaKey_Free(&dk);
    }
  #else
    (void)dok; (void)dres; (void)dsigLen;
    NA("ML-DSA sign");
  #endif
#else
    NA("ML-DSA sign");
#endif
}

int main(void)
{
    WC_RNG rng;
    int ret;

    XMEMSET(buf, 0x5a, sizeof(buf));
    banner();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("rng init failed %d\n", ret);
        return 1;
    }

    bench_hashes();
    bench_hmac();
    bench_aead();
#ifdef HAVE_ECC
    bench_ecc(&rng);
#endif
    bench_25519(&rng);
    bench_rsa(&rng);
    bench_pqc(&rng);

    wc_FreeRng(&rng);
    return 0;
}
