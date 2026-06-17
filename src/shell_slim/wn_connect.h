/* wn_connect.h
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

/**
 * TLS 1.3 client handshake driver (RFC 8446) for the external-PSK + ECDHE
 * (psk_dhe_ke) flow. Transport-agnostic via I/O callbacks; caller-provided
 * scratch buffer; no allocation. Certificates are out of scope (Phase 4).
 */

#ifndef WN_CONNECT_H
#define WN_CONNECT_H

#include "wolfnano.h"
#include "wolfnano_crypto.h"

/* Send/recv callbacks: return bytes transferred, or < 0 on error. */
typedef int (*wn_IoSend)(void* ctx, const byte* buf, word32 len);
typedef int (*wn_IoRecv)(void* ctx, byte* buf, word32 len);

/* Perform a TLS 1.3 PSK+ECDHE handshake as a client. Returns WOLFNANOTLS_SUCCESS
 * once the server Finished verifies and the client Finished is sent. */
WOLFNANOTLS_API int wn_Connect_Psk(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv,
                                void* ioCtx, const byte* psk, word32 pskLen,
                                const char* identity, byte* scratch,
                                word32 scratchLen);

#endif /* WN_CONNECT_H */
