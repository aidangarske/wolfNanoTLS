/* Minimal full-wolfSSL TLS 1.3 client config for the whole-deployment footprint
 * comparison (the baseline wolfNanoTLS slims down from). Same crypto scope as the
 * wolfNanoTLS/mbedTLS clients: TLS 1.3 client only, ECDHE P-256, AES-GCM, SHA-256,
 * X.509 cert verify (RSA + ECDSA). Picked up as "user_settings.h" via -Ibench/min/ws. */

#ifndef WS_FP_USER_SETTINGS_H
#define WS_FP_USER_SETTINGS_H

#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
#define NO_WOLFSSL_CLIENT
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK
#define NO_WRITEV

#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define HAVE_AESGCM
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define HAVE_ECC384
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WC_RSA_PSS
#define WOLFSSL_RSA_VERIFY_ONLY
#define WOLFSSL_RSA_PUBLIC_ONLY

/* X.509 cert verify, smallest */
#define WOLFSSL_SMALL_CERT_VERIFY
#define NO_ASN_TIME

/* generic SP math (matches the wolfNanoTLS clients' math config; no micro knobs) */
#define WOLFSSL_SP_MATH_ALL

/* size cuts */
#define NO_MD5
#define NO_SHA
#define NO_DES3
#define NO_RC4
#define NO_DSA
#define NO_DH
#define NO_PSK
#define NO_PWDBASED
#define NO_PKCS12
#define NO_PKCS7
#define NO_ERROR_STRINGS
#define NO_SESSION_CACHE

#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_SEED wn_fp_seed
#ifndef __ASSEMBLER__
extern int wn_fp_seed(unsigned char* output, unsigned int sz);
#endif

#endif /* WS_FP_USER_SETTINGS_H */
