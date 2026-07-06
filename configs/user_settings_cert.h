/* user_settings_cert.h
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

/* wolfNanoTLS X.509 client: TLS 1.3 ECDHE P-256 with server-cert verification
 * (ECDSA P-256/P-384, RSA-PSS). Server-auth only. ~60 KB .text on Cortex-M33
 * (docs/Footprint.md). Copy to your project as user_settings.h. */

#ifndef WOLFNANO_USER_SETTINGS_H
#define WOLFNANO_USER_SETTINGS_H

#define WOLFCRYPT_ONLY

#define WOLFSSL_SHA384
#define HAVE_HKDF
#define HAVE_AESGCM
#define HAVE_ECC
#define HAVE_ECC384
#define WOLFNANO_HAVE_ECDHE_P256
#define WOLFNANO_HAVE_RSA_VERIFY
#define WOLFNANO_X509

#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WOLFNANO_USER_SETTINGS_H */
