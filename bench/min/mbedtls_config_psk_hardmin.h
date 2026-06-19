/* mbedTLS hard-minimized TLS 1.3 PSK + ECDHE(X25519) client config. Builds on
 * mbedtls_config_psk.h (X.509/PK/RSA/TLS1.2 already stripped) and additionally:
 *   - enables MBEDTLS_PSA_CRYPTO_CONFIG with a minimal PSA_WANT_* crypto config
 *     so the PSA dispatch layer keeps only AES-GCM/SHA-256/HKDF/ECDH;
 *   - drops SHA-384/512, the non-GCM AES modes, and the P-256 curve (X25519
 *     only), none of which a TLS_AES_128_GCM_SHA256 + X25519 client uses.
 * This is the fair, like-for-like config behind the Footprint comparison. */

#ifndef WN_FP_MB_PSK_HARDMIN_CONFIG_H
#define WN_FP_MB_PSK_HARDMIN_CONFIG_H

#include "mbedtls_config_psk.h"

#define MBEDTLS_PSA_CRYPTO_CONFIG
#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "mbedtls_crypto_config_psk.h"

/* X25519 only */
#undef MBEDTLS_ECP_DP_SECP256R1_ENABLED

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

#endif /* WN_FP_MB_PSK_HARDMIN_CONFIG_H */
