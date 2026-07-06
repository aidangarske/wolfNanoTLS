/* user_settings_cert_pin.h
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

/* wolfNanoTLS X.509 client, key-pin only: same cert path as user_settings_cert.h
 * but with hostname matching compiled out (WOLFNANO_X509_HOSTNAME 0), ~1 KB
 * smaller. For embedded devices that authenticate one fixed server by an exact
 * leaf-key pin via wn_Connect_CertName(serverName=NULL, pinnedKey=...).
 * Copy to your project as user_settings.h. */

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
#define WOLFNANO_X509_HOSTNAME 0     /* pin-only: drop SAN/CN matching (~1 KB) */

#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WOLFNANO_USER_SETTINGS_H */
