/* user_settings_cert_pqc.h
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

/* wolfNanoTLS post-quantum HTTPS client: X25519MLKEM768 hybrid key exchange
 * (harvest-now-decrypt-later resistant) with classical X.509 server-cert
 * verification (ECDSA P-256/P-384, RSA-PSS). ~74 KB .text on Cortex-M33
 * (docs/Footprint.md). Copy to your project as user_settings.h. */

#ifndef WOLFNANO_USER_SETTINGS_H
#define WOLFNANO_USER_SETTINGS_H

#define WOLFCRYPT_ONLY

#define WOLFNANO_HAVE_SHA256
#define WOLFNANO_HAVE_SHA384
#define WOLFNANO_HAVE_HKDF
#define WOLFNANO_HAVE_AESGCM
#define WOLFNANO_HAVE_ECC
#define WOLFNANO_HAVE_ECC384
#define WOLFNANO_HAVE_ECDHE_P256
#define WOLFNANO_HAVE_RSA_VERIFY
#define WOLFNANO_HAVE_MLKEM_HYBRID
#define WOLFNANO_X509

#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WOLFNANO_USER_SETTINGS_H */
