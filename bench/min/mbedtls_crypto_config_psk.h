/* Minimal PSA crypto config for a TLS 1.3 PSK + ECDHE(X25519) client using
 * AES-128-GCM + SHA-256 + HKDF. Selected via MBEDTLS_PSA_CRYPTO_CONFIG so the
 * PSA dispatch layer keeps only these mechanisms (the stock crypto_config.h
 * enables every algorithm, which is the bulk of a default mbedTLS 3.6 build).
 * Used by mbedtls_config_psk.h in the footprint comparison. */

#ifndef WN_FP_MB_PSK_CRYPTO_CONFIG_H
#define WN_FP_MB_PSK_CRYPTO_CONFIG_H

#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_HMAC                       1
#define PSA_WANT_ALG_HKDF                       1
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_ECDH                       1

#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_DERIVE                1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1

#define PSA_WANT_ECC_MONTGOMERY_255             1

#endif /* WN_FP_MB_PSK_CRYPTO_CONFIG_H */
