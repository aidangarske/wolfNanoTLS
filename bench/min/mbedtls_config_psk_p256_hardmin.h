/* mbedTLS hard-minimized TLS 1.3 PSK + ECDHE(P-256) client config. P-256
 * variant of mbedtls_config_psk_hardmin.h: minimal PSA config (secp256r1),
 * X25519 dropped, plus SHA-384/512, non-GCM AES modes, and restartable-ECP
 * stripped. The fair, like-for-like config behind the P-256 Footprint row. */

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

#endif /* WN_FP_MB_PSK_P256_HARDMIN_CONFIG_H */
