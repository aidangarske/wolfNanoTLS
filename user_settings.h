/* user_settings.h
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

#ifndef WOLFNANO_USER_SETTINGS_H
#define WOLFNANO_USER_SETTINGS_H

/* The one wolfNano config file. Provider backend = src (default). */

/* Phase 1: crypto floor only (no TLS shell yet). */
#define WOLFCRYPT_ONLY

/* ---- wolfNano feature selection (WOLFNANO_HAVE_*) ---- */
#define WOLFNANO_HAVE_SHA256
#define WOLFNANO_HAVE_SHA384
#define WOLFNANO_HAVE_HKDF
#define WOLFNANO_HAVE_AESGCM
#define WOLFNANO_HAVE_ECC
#define WOLFNANO_HAVE_ECC384
#define WOLFNANO_HAVE_CURVE25519
#define WOLFNANO_HAVE_ED25519

#include "wolfnano_target.h"   /* target → asm/SP bundle (one macro selects) */
#include "wolfnano_config.h"   /* WOLFNANO_HAVE_* → wolfSSL macros + size cuts */

#endif /* WOLFNANO_USER_SETTINGS_H */
