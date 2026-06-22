/* user_settings_baremetal.h
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

/* Generic no-OS / baremetal MCU build (portable C, no asm bundle): minimal PSK
 * + X25519 floor. The integration must provide entropy via wn_seed() and the
 * transport via the wn_IoSend / wn_IoRecv callbacks. Pick an asm bundle with a
 * WOLFNANOTLS_TARGET_* device profile when one fits. Copy as user_settings.h. */

#ifndef WOLFNANOTLS_USER_SETTINGS_H
#define WOLFNANOTLS_USER_SETTINGS_H

#ifndef WOLFNANOTLS_TARGET_PORTABLE_C
    #define WOLFNANOTLS_TARGET_PORTABLE_C
#endif

#define WOLFCRYPT_ONLY

#define WOLFNANOTLS_HAVE_SHA256
#define WOLFNANOTLS_HAVE_HKDF
#define WOLFNANOTLS_HAVE_AESGCM
#define WOLFNANOTLS_HAVE_CURVE25519

#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WOLFNANOTLS_USER_SETTINGS_H */
