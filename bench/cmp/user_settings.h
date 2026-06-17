/* user_settings.h (bench comparison only)
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNano.
 *
 * wolfNano is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNano is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* Minimal TLS 1.3 config used only to compile wolfSSL's TLS-layer sources for a
 * footprint comparison against the wolfNano slim shell. Not a wolfNano build. */

#ifndef WOLFNANO_BENCH_CMP_SETTINGS_H
#define WOLFNANO_BENCH_CMP_SETTINGS_H

#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define HAVE_AESGCM
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_HASHDRBG
#define WOLFSSL_SP_MATH_ALL
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_USER_IO
#define NO_DH
#define NO_RSA

#endif /* WOLFNANO_BENCH_CMP_SETTINGS_H */
