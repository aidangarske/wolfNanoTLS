/* user_settings.h
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

#ifndef WOLFNANO_USER_SETTINGS_H
#define WOLFNANO_USER_SETTINGS_H

/* The one wolfNanoTLS config file. Provider backend = src (default). */

/* Phase 1: crypto floor only (no TLS shell yet). */
#define WOLFCRYPT_ONLY

/* ---- crypto capabilities (wolfSSL's own macros; SHA-256 is on by default) ---- */
#define WOLFSSL_SHA384
#define HAVE_HKDF
#define HAVE_AESGCM
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_CURVE25519
#define HAVE_ED25519

/* Memory model: default is plain wolfSSL (heap). Define WOLFSSL_SMALL_STACK
 * (embedded) or WOLFSSL_NO_MALLOC (zero dynamic allocation) to change it. */

#include "wolfnano_target.h"   /* target → asm/SP bundle (one macro selects) */
#include "wolfnano_config.h"   /* capability completion + standing size cuts */

#endif /* WOLFNANO_USER_SETTINGS_H */
