/* wolfnano_config.h
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

#ifndef WOLFNANO_CONFIG_H
#define WOLFNANO_CONFIG_H

/* Translate WOLFNANO_HAVE_* selections to wolfSSL macros, apply the standing
 * size cuts, and set the memory model. Include only macro definitions here:
 * no wolfSSL headers (this is pulled in early from user_settings.h). */

/* ---- standing size cuts (always) ---- */
#define NO_OLD_TLS
#define NO_MD5
#define NO_MD4
#define NO_SHA            /* SHA-1 */
#define NO_DES3
#define NO_RC4
#define NO_DSA
#define NO_DH
/* RSA off unless the verify adder is enabled (real-world cert chains). */
#ifndef WOLFNANO_HAVE_RSA_VERIFY
    #define NO_RSA
#endif
#define NO_PWDBASED
#define NO_PKCS12
#define NO_SIG_WRAPPER     /* shell calls wc_* directly, not the wrapper */
#define NO_AES_CBC         /* TLS 1.3 is AEAD-only */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_ERROR_STRINGS

/* No cert-time validation until the X.509 adder (which brings a time hook); a
 * clockless cert build (WOLFNANO_NO_X509_TIME) drops the ASN time path too. */
#if !defined(WOLFNANO_X509) || defined(WOLFNANO_NO_X509_TIME)
    #define NO_ASN_TIME
#endif

/* ---- X.509 adder (minimal cert path validation) ---- */
#ifdef WOLFNANO_X509
    #define WOLFSSL_SMALL_CERT_VERIFY  /* low-memory cert signature check */
    /* Hostname (SAN/CN) identity matching is on by default; a pin-only cert
     * build may set WOLFNANO_X509_HOSTNAME 0 to drop ~1 KB and rely on an
     * exact SPKI pin instead. */
    #ifndef WOLFNANO_X509_HOSTNAME
        #define WOLFNANO_X509_HOSTNAME 1
    #endif
    #if defined(WOLFNANO_X509_HOSTNAME) && (WOLFNANO_X509_HOSTNAME == 0)
        #undef WOLFNANO_X509_HOSTNAME
    #endif
#endif

/* ---- RSA verify adder (RSA-signed cert chains, RSA-PSS for TLS 1.3) ----
 * Verify/public-only by default; WOLFNANO_RSA_FULL adds keygen/sign (needs
 * working memory) for tooling such as the benchmark. */
#ifdef WOLFNANO_HAVE_RSA_VERIFY
    #ifndef WOLFNANO_RSA_FULL
        #define WOLFSSL_RSA_VERIFY_ONLY
        #define WOLFSSL_RSA_PUBLIC_ONLY
    #else
        #define WOLFSSL_KEY_GEN
    #endif
    #define WC_RSA_PSS
    /* Real-world roots are RSA-4096 (e.g. ISRG Root X1); the SP default caps at
     * 3072, so raise the verify ceiling so public CA chains validate. */
    #ifndef RSA_MAX_SIZE
        #define RSA_MAX_SIZE 4096
    #endif
    #ifndef SP_INT_BITS
        #define SP_INT_BITS 4096
    #endif
    /* SP_INT_BITS only covers the generic sp_int engine; specialized SP backends
     * gate RSA modulus sizes at compile time, so enable the 4096 path there too. */
    #if defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_4096)
        #define WOLFSSL_SP_4096
    #endif
#endif

/* ---- side-channel hardening (constant-time) ---- */
#define ECC_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ---- RNG: Hash-DRBG seeded through a pluggable wolfNano seed hook ----
 * The seed source is supplied by the integration (getentropy on a host now; a
 * hardware TRNG / wolfHAL RNG driver later). The DRBG itself stays the
 * validated Hash-DRBG; only the seed is pluggable. */
#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_SEED wn_seed
#ifndef __ASSEMBLER__
extern int wn_seed(unsigned char* output, unsigned int sz);
#endif

/* ---- memory model: true no-allocator (wolfCOSE bar) ---- *
 * Pass -DWOLFNANO_ALLOW_MALLOC during bring-up to temporarily relax. */
#ifndef WOLFNANO_ALLOW_MALLOC
    #define WOLFSSL_NO_MALLOC
    #define WOLFSSL_SP_NO_MALLOC
#endif

/* ---- X25519MLKEM768 hybrid key exchange: pulls in ML-KEM-768 + X25519 ---- */
#ifdef WOLFNANO_HAVE_MLKEM_HYBRID
    #ifndef WOLFNANO_MLKEM
        #define WOLFNANO_MLKEM
    #endif
    #ifndef WOLFNANO_HAVE_CURVE25519
        #define WOLFNANO_HAVE_CURVE25519
    #endif
#endif

/* ---- hashes ---- */
#ifndef WOLFNANO_HAVE_SHA256
    #define NO_SHA256
#endif
#ifdef WOLFNANO_HAVE_SHA384
    #define WOLFSSL_SHA384
    #define WOLFSSL_SHA512
#endif

/* ---- HKDF (TLS 1.3 key schedule) ---- */
#ifdef WOLFNANO_HAVE_HKDF
    #define HAVE_HKDF
#endif

/* ---- AEAD ---- */
#ifdef WOLFNANO_HAVE_AESGCM
    #define HAVE_AESGCM
#else
    #define NO_AES
#endif
#ifdef WOLFNANO_HAVE_CHACHA
    #define HAVE_CHACHA
    #define HAVE_POLY1305
#endif

/* ---- ECC (ECDHE + ECDSA), user-selected curves only ---- */
#ifdef WOLFNANO_HAVE_ECC
    #define HAVE_ECC
    #define ECC_USER_CURVES   /* P-256 stays unless NO_ECC256; others opt-in */
    #ifdef WOLFNANO_HAVE_ECC384
        #define HAVE_ECC384
    #endif
#endif

/* ---- X25519 ---- */
#ifdef WOLFNANO_HAVE_CURVE25519
    #define HAVE_CURVE25519
#endif

/* ---- approved-mode (fips backend): X25519/ChaCha are outside the wolfCrypt
 * FIPS boundary, so an approved build negotiates ECDHE P-256 + AES-GCM only. */
#ifdef WOLFNANO_FIPS
    /* The X25519MLKEM768 hybrid group is outside the FIPS boundary and would
     * silently win the key-share selection (see wn_keyshare.h), so reject the
     * combination rather than ship a non-approved group in an approved build. */
    #if defined(WOLFNANO_HAVE_MLKEM_HYBRID)
        #error "WOLFNANO_FIPS cannot be combined with WOLFNANO_HAVE_MLKEM_HYBRID"
    #endif
    #ifndef WOLFNANO_HAVE_ECDHE_P256
        #define WOLFNANO_HAVE_ECDHE_P256
    #endif
#endif

/* ---- Ed25519 (requires SHA-512) ---- */
#ifdef WOLFNANO_HAVE_ED25519
    #define HAVE_ED25519
    #ifndef WOLFSSL_SHA512
        #define WOLFSSL_SHA512
    #endif
#endif

/* ---- PQC adders (compile-out-able) ---- */
#ifdef WOLFNANO_MLKEM
    #define WOLFSSL_HAVE_MLKEM
    #define WOLFSSL_WC_ML_KEM           /* wolfCrypt implementation */
    #define WOLFSSL_WC_ML_KEM_768       /* ML-KEM-768 only */
    #define WOLFSSL_NO_ML_KEM_512
    #define WOLFSSL_NO_ML_KEM_1024
    #ifndef WOLFSSL_SHA3
        #define WOLFSSL_SHA3
    #endif
    #define WOLFSSL_SHAKE128
    #define WOLFSSL_SHAKE256
#endif

#ifdef WOLFNANO_MLDSA
    #define WOLFSSL_HAVE_MLDSA
    /* Default ML-DSA-44 (NIST level 2): security-balanced with the 128-bit
     * suite (X25519/P-256/AES-128) and the smallest keys/signatures. Opt into
     * level 3 (65) or 5 (87) with WOLFNANO_MLDSA_LEVEL when required. */
    #ifndef WOLFNANO_MLDSA_LEVEL
        #define WOLFNANO_MLDSA_LEVEL 2
    #endif
    #if WOLFNANO_MLDSA_LEVEL == 2
        #define WOLFSSL_NO_ML_DSA_65
        #define WOLFSSL_NO_ML_DSA_87
        #define WN_MLDSA_SCHEME 0x0904
    #elif WOLFNANO_MLDSA_LEVEL == 3
        #define WOLFSSL_NO_ML_DSA_44
        #define WOLFSSL_NO_ML_DSA_87
        #define WN_MLDSA_SCHEME 0x0905
    #elif WOLFNANO_MLDSA_LEVEL == 5
        #define WOLFSSL_NO_ML_DSA_44
        #define WOLFSSL_NO_ML_DSA_65
        #define WN_MLDSA_SCHEME 0x0906
    #else
        #error "WOLFNANO_MLDSA_LEVEL must be 2 (ML-DSA-44), 3 (65), or 5 (87)"
    #endif
    /* Default: verify-only, no-allocation (the wolfNano client cert-verify
     * path). WOLFNANO_MLDSA_SIGN adds keygen/sign (needs working memory). */
    #ifndef WOLFNANO_MLDSA_SIGN
        #define WOLFSSL_MLDSA_VERIFY_ONLY
        #define WOLFSSL_MLDSA_VERIFY_NO_MALLOC
    #endif
    #ifndef WOLFSSL_SHA3
        #define WOLFSSL_SHA3
    #endif
    #ifndef WOLFSSL_SHAKE128
        #define WOLFSSL_SHAKE128
    #endif
    #ifndef WOLFSSL_SHAKE256
        #define WOLFSSL_SHAKE256
    #endif
#endif

#endif /* WOLFNANO_CONFIG_H */
