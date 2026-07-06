/* user_settings_cert_mldsa.h
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

/* wolfNanoTLS post-quantum X.509 client: TLS 1.3 ECDHE P-256 with ML-DSA-44
 * server-cert verification (verify-only, no RSA). Set WOLFNANO_MLDSA_LEVEL=3/5
 * for ML-DSA-65/87. Copy to your project as user_settings.h. */

#ifndef WOLFNANO_USER_SETTINGS_H
#define WOLFNANO_USER_SETTINGS_H

#define WOLFCRYPT_ONLY

#define WOLFSSL_SHA384
#define HAVE_HKDF
#define HAVE_AESGCM
#define HAVE_ECC
#define WOLFNANO_HAVE_ECDHE_P256
#define WOLFNANO_X509
#define WOLFNANO_MLDSA

#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WOLFNANO_USER_SETTINGS_H */
