/* Minimal wolfcrypt config for the footprint comparison (picked up as
 * "user_settings.h" by putting bench/min first on the include path). Enables
 * only the families a TLS 1.3 / secure-boot scope needs; --gc-sections trims
 * each program to exactly what it calls. */

#ifndef WN_FP_USER_SETTINGS_H
#define WN_FP_USER_SETTINGS_H

#define WOLFCRYPT_ONLY     /* no wolfSSL TLS layer; wolfNanoTLS has its own shell */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_USER_IO
#define NO_OLD_TLS
#define WOLFSSL_NO_TLS12
#define NO_MD5
#define NO_SHA
#define NO_DES3
#define NO_RC4
#define NO_DSA
#define NO_DH
#define NO_RSA
#define NO_PWDBASED
#define NO_PKCS12
#define NO_PKCS7
#define NO_ASN_TIME
#define NO_ERROR_STRINGS
#define NO_SIG_WRAPPER
#define NO_AES_CBC
#define WC_NO_RNG_SIMPLE

/* smallest ECC: specialized small single-precision P-256 (sp_c32.c), no asm,
 * no generic big-int engine. WOLFSSL_SP_MATH (not _ALL) + WOLFSSL_SP_SMALL. */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
#define SP_WORD_SIZE 32

/* size-minimization knobs */
#define GCM_SMALL                  /* no GHASH tables */
#define WOLFSSL_AES_SMALL_TABLES   /* compact AES tables */
#define WOLFSSL_SHA256_SMALL       /* compact SHA-256 */
#define WOLFSSL_SP_NO_DYN_STACK

/* enabled families (gc-sections drops unused functions per scope) */
#define HAVE_AESGCM
#define WOLFSSL_AES_128
#define HAVE_HKDF
#define HAVE_HMAC
#define HAVE_ECC
#define ECC_USER_CURVES          /* P-256 only */
#define HAVE_ECC256
#define HAVE_HASHDRBG
#define ECC_TIMING_RESISTANT

/* bare-metal seed hook (stubbed in the test program) */
#define CUSTOM_RAND_GENERATE_SEED wn_fp_seed
#ifndef __ASSEMBLER__
extern int wn_fp_seed(unsigned char* output, unsigned int sz);
#endif

#endif /* WN_FP_USER_SETTINGS_H */
