/* Minimal full-wolfSSL TLS 1.3 PSK (+ECDHE/X25519) client config, no certs —
 * matches the wolfNanoTLS PSK client scope. */

#ifndef WSP_FP_USER_SETTINGS_H
#define WSP_FP_USER_SETTINGS_H

#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
#define NO_WOLFSSL_SERVER
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK
#define NO_WRITEV

#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define HAVE_AESGCM
#define HAVE_CURVE25519          /* X25519 ECDHE key share */

#define NO_CERTS                 /* PSK only: no X.509/cert chain */
#define NO_RSA
#define NO_ASN

#define WOLFSSL_SP_MATH_ALL

/* size cuts */
#define NO_MD5
#define NO_SHA
#define NO_DES3
#define NO_RC4
#define NO_DSA
#define NO_DH
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

#endif /* WSP_FP_USER_SETTINGS_H */
