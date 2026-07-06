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
 * WOLFNANO_TARGET_* device profile when one fits. Copy as user_settings.h. */

#ifndef WOLFNANO_USER_SETTINGS_H
#define WOLFNANO_USER_SETTINGS_H

#ifndef WOLFNANO_TARGET_PORTABLE_C
    #define WOLFNANO_TARGET_PORTABLE_C
#endif

#define WOLFCRYPT_ONLY

#define HAVE_HKDF
#define HAVE_AESGCM
#define HAVE_CURVE25519

#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_SHA256_SMALL

#include "wolfnano_target.h"
#include "wolfnano_config.h"

#endif /* WOLFNANO_USER_SETTINGS_H */
