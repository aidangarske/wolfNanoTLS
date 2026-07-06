/* Minimal wolfNanoTLS config for the smallest TLS 1.3 client footprint: ECDHE
 * P-256 + AES-128-GCM + SHA-256 + ECDSA/RSA cert verify. No SHA-384, P-384,
 * X25519-sig, Ed25519; size knobs on. Picked up as user_settings.h via -I. */

#ifndef WNC_MIN_USER_SETTINGS_H
#define WNC_MIN_USER_SETTINGS_H

#define WOLFCRYPT_ONLY

#define WOLFSSL_SHA384       /* shell transcript/keyschedule reference it */
#define HAVE_HKDF
#define HAVE_AESGCM
#define HAVE_ECC
#define HAVE_CURVE25519   /* shell keyshare references X25519 (until gated) */

/* size knobs */
#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WNC_MIN_USER_SETTINGS_H */
