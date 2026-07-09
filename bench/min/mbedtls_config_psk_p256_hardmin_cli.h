/* mbedTLS hard-minimized TLS 1.3 PSK + ECDHE(P-256) client-only config: the
 * P-256 PSK base with MBEDTLS_SSL_SRV_C stripped, so the footprint is a pure
 * TLS 1.3 client (the both-roles base is the device config). */

#ifndef WN_FP_MB_PSK_P256_HARDMIN_CONFIG_H
#define WN_FP_MB_PSK_P256_HARDMIN_CONFIG_H

#include "mbedtls_config_psk.h"

#define MBEDTLS_PSA_CRYPTO_CONFIG
#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "mbedtls_crypto_config_psk_p256.h"

/* P-256 only */
#undef MBEDTLS_ECP_DP_CURVE25519_ENABLED

/* SHA-256 is the only hash this ciphersuite needs */
#undef MBEDTLS_SHA384_C
#undef MBEDTLS_SHA512_C

/* AES-GCM only: drop the other block-cipher modes */
#undef MBEDTLS_CIPHER_MODE_CBC
#undef MBEDTLS_CIPHER_MODE_CFB
#undef MBEDTLS_CIPHER_MODE_OFB
#undef MBEDTLS_CIPHER_MODE_CTR
#undef MBEDTLS_CIPHER_MODE_XTS

#undef MBEDTLS_ECP_RESTARTABLE

#undef MBEDTLS_SSL_SRV_C
#endif /* WN_FP_MB_PSK_P256_HARDMIN_CONFIG_H */
