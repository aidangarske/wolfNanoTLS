/* Minimal MbedTLS config for the footprint comparison: only the modules a
 * TLS 1.3 ciphersuite's crypto needs (AES-GCM, SHA-256, HKDF, ECDHE/ECDSA
 * P-256). No TLS layer, no entropy/DRBG (the test passes a dummy f_rng), no
 * filesystem/net. --gc-sections trims each program to its scope. */

#ifndef WN_FP_MBEDTLS_CONFIG_H
#define WN_FP_MBEDTLS_CONFIG_H

#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

#define MBEDTLS_HAVE_ASM

/* size-minimization knobs */
#define MBEDTLS_AES_FEWER_TABLES
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_ECP_WINDOW_SIZE        2
#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0

#endif /* WN_FP_MBEDTLS_CONFIG_H */
