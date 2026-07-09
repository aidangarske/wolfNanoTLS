#ifndef WS_FP_P256_USER_SETTINGS_H
#define WS_FP_P256_USER_SETTINGS_H

#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
/* both roles (device) */
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
#define HAVE_CURVE25519

/* P-256 / SHA-256 only private PKI: no SHA-384/512, no P-384, no RSA, no Ed25519 */
#define NO_RSA
#define WOLFSSL_SMALL_CERT_VERIFY
#define NO_ASN_TIME
#define WOLFSSL_SP_MATH_ALL

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

#endif
