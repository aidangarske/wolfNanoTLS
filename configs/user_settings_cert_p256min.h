/* user_settings_cert_p256min.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNanoTLS.
 *
 * wolfNanoTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNanoTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* wolfNanoTLS X.509 client locked to a single-curve, single-hash private PKI:
 * TLS 1.3 ECDHE P-256, and a cert chain that is ECDSA P-256 with ECDSA-SHA256
 * signatures end to end. Drops SHA-384/512, P-384, RSA, and Ed25519, so the
 * parser recognizes only P-256 + ECDSA-SHA256 and the crypto floor omits
 * rsa.c/sha512.c. ~35 KB .text on Cortex-M33 vs ~53 KB for user_settings_cert.h.
 *
 * Scope: this authenticates a chain you issue yourself as P-256/SHA-256. It
 * CANNOT verify a typical public-web chain (public intermediates are commonly
 * ECDSA-SHA384 and roots RSA); use user_settings_cert.h for general HTTPS.
 * Copy to your project as user_settings.h. */

#ifndef WOLFNANO_USER_SETTINGS_H
#define WOLFNANO_USER_SETTINGS_H

#define WOLFCRYPT_ONLY

#define WOLFNANO_HAVE_SHA256
#define WOLFNANO_HAVE_HKDF
#define WOLFNANO_HAVE_AESGCM
#define WOLFNANO_HAVE_ECC
#define WOLFNANO_HAVE_ECDHE_P256
#define WOLFNANO_X509

#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WOLFNANO_USER_SETTINGS_H */
