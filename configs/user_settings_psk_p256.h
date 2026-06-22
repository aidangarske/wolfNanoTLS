/* user_settings_psk_p256.h
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

/* wolfNanoTLS client: TLS 1.3 PSK + ECDHE P-256, AES-128-GCM, SHA-256. P-256 is
 * the broad-interop / FIPS-approved curve. ~25 KB .text on Cortex-M33
 * (docs/Footprint.md). Copy to your project as user_settings.h. */

#ifndef WOLFNANOTLS_USER_SETTINGS_H
#define WOLFNANOTLS_USER_SETTINGS_H

#define WOLFCRYPT_ONLY

#define WOLFNANOTLS_HAVE_SHA256
#define WOLFNANOTLS_HAVE_HKDF
#define WOLFNANOTLS_HAVE_AESGCM
#define WOLFNANOTLS_HAVE_ECC
#define WOLFNANOTLS_HAVE_ECDHE_P256

#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WOLFNANOTLS_USER_SETTINGS_H */
