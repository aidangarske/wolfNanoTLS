/* wolfnano.h
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

/**
 * wolfNano public API surface: shared types and return codes.
 */

#ifndef WOLFNANO_H
#define WOLFNANO_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#define WOLFNANO_API
#define WOLFNANO_LOCAL

/* Return codes: success is 0, errors are negative. The first four are stable;
 * the granular handshake codes (-4..-9) map to TLS alerts (see wn_connect.c). */
#define WOLFNANO_SUCCESS          0
#define WOLFNANO_E_INVALID_ARG  (-1)
#define WOLFNANO_E_CRYPTO       (-2)
#define WOLFNANO_E_UNSUPPORTED  (-3)
#define WOLFNANO_E_BAD_STATE    (-4)   /* internal handshake-state error */
#define WOLFNANO_E_UNEXPECTED_MSG (-5) /* message not allowed in this state */
#define WOLFNANO_E_DECODE       (-6)   /* malformed handshake message */
#define WOLFNANO_E_BAD_MAC      (-7)   /* Finished / record auth failure */
#define WOLFNANO_E_ILLEGAL_PARAM (-8)  /* bad group / version / param */
#define WOLFNANO_E_BAD_CERT     (-9)   /* certificate / CertVerify failure */
#define WOLFNANO_E_CLOSED       (-10)  /* peer sent close_notify */

/* Transport callbacks: return bytes transferred, or < 0 on error. */
typedef int (*wn_IoSend)(void* ctx, const byte* buf, word32 len);
typedef int (*wn_IoRecv)(void* ctx, byte* buf, word32 len);

/* Short human-readable string for a return code (static, never NULL). */
WOLFNANO_API const char* wn_ErrorToString(int err);

#endif /* WOLFNANO_H */
