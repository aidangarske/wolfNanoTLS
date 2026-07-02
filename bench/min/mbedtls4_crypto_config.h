/* mbedTLS 4.x PSA (TF-PSA-Crypto) config for the footprint compare: start from
 * the stock crypto_config.h and disable everything outside the minimal TLS 1.3
 * client scope. Kept: ECDHE (secp256r1 + x25519), AES-128-GCM, SHA-256/384,
 * HKDF/HMAC, ECDSA (P-256) + RSA (PSS + PKCS1v15 verify), external RNG. */

#ifndef WN_FP_MB4_CRYPTO_CONFIG_H
#define WN_FP_MB4_CRYPTO_CONFIG_H

#include "psa/crypto_config.h"

/* external RNG: the harness supplies randomness, so drop entropy + DRBG */
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#undef MBEDTLS_CTR_DRBG_C
#undef MBEDTLS_HMAC_DRBG_C
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#undef PSA_WANT_ALG_DETERMINISTIC_ECDSA

/* host-only storage / filesystem / time / self-test */
#undef MBEDTLS_FS_IO
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE

/* no PEM/base64 (DER certs only), no key/CSR writing */
#undef MBEDTLS_PEM_PARSE_C
#undef MBEDTLS_PEM_WRITE_C
#undef MBEDTLS_BASE64_C
#undef MBEDTLS_PK_WRITE_C

/* drop unused crypto modules */
#undef MBEDTLS_PKCS5_C
#undef MBEDTLS_NIST_KW_C
#undef MBEDTLS_LMS_C
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_AESCE_C

/* ---- AEAD / cipher modes: keep AES-GCM only ---- */
#undef PSA_WANT_ALG_CBC_NO_PADDING
#undef PSA_WANT_ALG_CBC_PKCS7
#undef PSA_WANT_ALG_CCM
#undef PSA_WANT_ALG_CCM_STAR_NO_TAG
#undef PSA_WANT_ALG_CMAC
#undef PSA_WANT_ALG_CFB
#undef PSA_WANT_ALG_CHACHA20_POLY1305
#undef PSA_WANT_ALG_CTR
#undef PSA_WANT_ALG_ECB_NO_PADDING
#undef PSA_WANT_ALG_OFB
#undef PSA_WANT_ALG_STREAM_CIPHER

/* drop FFDH / J-PAKE / RSA encrypt */
#undef PSA_WANT_ALG_FFDH
#undef PSA_WANT_ALG_JPAKE
#undef PSA_WANT_ALG_RSA_OAEP
#undef PSA_WANT_ALG_RSA_PKCS1V15_CRYPT

/* drop unused KDFs / PRFs */
#undef PSA_WANT_ALG_PBKDF2_HMAC
#undef PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128
#undef PSA_WANT_ALG_TLS12_PRF
#undef PSA_WANT_ALG_TLS12_PSK_TO_MS
#undef PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS

/* drop unused hashes (keep SHA-256 + SHA-384; SHA-512 backs SHA-384) */
#undef PSA_WANT_ALG_MD5
#undef PSA_WANT_ALG_RIPEMD160
#undef PSA_WANT_ALG_SHA_1
#undef PSA_WANT_ALG_SHA_224
#undef PSA_WANT_ALG_SHA3_224
#undef PSA_WANT_ALG_SHA3_256
#undef PSA_WANT_ALG_SHA3_384
#undef PSA_WANT_ALG_SHA3_512
#undef PSA_WANT_ALG_SHAKE128
#undef PSA_WANT_ALG_SHAKE256

/* ---- curves: keep secp256r1 + x25519 only ---- */
#undef PSA_WANT_ECC_BRAINPOOL_P_R1_256
#undef PSA_WANT_ECC_BRAINPOOL_P_R1_384
#undef PSA_WANT_ECC_BRAINPOOL_P_R1_512
#undef PSA_WANT_ECC_MONTGOMERY_448
#undef PSA_WANT_ECC_SECP_K1_256
#undef PSA_WANT_ECC_SECP_R1_384
#undef PSA_WANT_ECC_SECP_R1_521

/* drop DH groups + DH key types */
#undef PSA_WANT_DH_RFC7919_2048
#undef PSA_WANT_DH_RFC7919_3072
#undef PSA_WANT_DH_RFC7919_4096
#undef PSA_WANT_DH_RFC7919_6144
#undef PSA_WANT_DH_RFC7919_8192
#undef PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY
#undef PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC
#undef PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT
#undef PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT
#undef PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE

/* drop unused symmetric key types (keep AES) */
#undef PSA_WANT_KEY_TYPE_ARIA
#undef PSA_WANT_KEY_TYPE_CAMELLIA
#undef PSA_WANT_KEY_TYPE_CHACHA20
#undef PSA_WANT_KEY_TYPE_PASSWORD
#undef PSA_WANT_KEY_TYPE_PASSWORD_HASH

/* no client cert: drop RSA key-pair generation/import (keep RSA public key
 * for server-cert verify). ECC key pair kept for ephemeral ECDHE. */
#undef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC
#undef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT
#undef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT
#undef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE

#endif /* WN_FP_MB4_CRYPTO_CONFIG_H */
