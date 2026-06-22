/* wn_connect.h
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
 * TLS 1.3 client handshake driver (RFC 8446) for the external-PSK + ECDHE
 * (psk_dhe_ke) flow. Transport-agnostic via I/O callbacks; caller-provided
 * scratch buffer; no allocation. Certificates are out of scope (Phase 4).
 */

#ifndef WN_CONNECT_H
#define WN_CONNECT_H

#include "wolfnano.h"
#include "wolfnano_crypto.h"
#include "wn_session.h"

/* wn_IoSend / wn_IoRecv transport callbacks are declared in wolfnano.h. */

/* Perform a TLS 1.3 PSK+ECDHE handshake as a client. Returns WOLFNANO_SUCCESS
 * once the server Finished verifies and the client Finished is sent. The
 * traffic keys are wiped before returning (handshake-only; use the _ex form to
 * keep a session for application data). */
WOLFNANO_API int wn_Connect_Psk(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv,
                                void* ioCtx, const byte* psk, word32 pskLen,
                                const char* identity, byte* scratch,
                                word32 scratchLen);

/* As wn_Connect_Psk, but on success fills sess with the application traffic
 * keys, the transport callbacks, and the scratch buffer, ready for wn_Send /
 * wn_Recv / wn_Close. */
WOLFNANO_API int wn_Connect_Psk_ex(wn_Session* sess, WC_RNG* rng,
                                   wn_IoSend ioSend, wn_IoRecv ioRecv,
                                   void* ioCtx, const byte* psk, word32 pskLen,
                                   const char* identity, byte* scratch,
                                   word32 scratchLen);

/* Perform a TLS 1.3 ECDHE handshake with server certificate authentication.
 * anchor is a pinned trust anchor (DER); the server's leaf must verify against
 * it and the CertificateVerify signature must verify with the leaf key.
 * The cert path keeps its large working buffers (handshake accumulator, record
 * plaintext, leaf SPKI) in scratch, so scratchLen must be at least ~13 KB.
 * Requires WOLFNANO_X509. Returns WOLFNANO_SUCCESS on a completed handshake. */
WOLFNANO_API int wn_Connect_Cert(WC_RNG* rng, wn_IoSend ioSend,
                                 wn_IoRecv ioRecv, void* ioCtx,
                                 const byte* anchor, word32 anchorLen,
                                 byte* scratch, word32 scratchLen);

/* As wn_Connect_Cert, but on success fills sess for application data. */
WOLFNANO_API int wn_Connect_Cert_ex(wn_Session* sess, WC_RNG* rng,
                                    wn_IoSend ioSend, wn_IoRecv ioRecv,
                                    void* ioCtx, const byte* anchor,
                                    word32 anchorLen, byte* scratch,
                                    word32 scratchLen);

#endif /* WN_CONNECT_H */
