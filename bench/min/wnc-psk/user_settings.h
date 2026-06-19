/* Minimal wolfNano config for the smallest TLS 1.3 PSK client: AES-128-GCM +
 * SHA-256 + HKDF + (EC)DHE only. No SHA-384/512 (so HMAC does not pull in the
 * SHA-512 transform), no Ed25519, no X.509. The handshake curve is chosen by
 * the build flag (default X25519; WOLFNANO_HAVE_ECDHE_P256 for P-256), and
 * gc-sections drops the unused curve. Picked up as user_settings.h via -I. */

#ifndef WNC_PSK_USER_SETTINGS_H
#define WNC_PSK_USER_SETTINGS_H

#define WOLFCRYPT_ONLY

#define WOLFNANO_HAVE_SHA256
#define WOLFNANO_HAVE_HKDF
#define WOLFNANO_HAVE_AESGCM
#define WOLFNANO_HAVE_ECC
#define WOLFNANO_HAVE_CURVE25519

/* size knobs */
#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WNC_PSK_USER_SETTINGS_H */
