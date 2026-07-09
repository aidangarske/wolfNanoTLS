/* wn_accept.h
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
 * TLS 1.3 external-PSK + ECDHE server handshake (RFC 8446). The server-side
 * mirror of wn_Connect_Psk; compile-time adder behind WOLFNANO_SERVER, off by
 * default. Transport via I/O callbacks; crypto via the wc_* seam; no allocation.
 */

#ifndef WN_ACCEPT_H
#define WN_ACCEPT_H

#include "wn_session.h"
#include "wolfnano_crypto.h"

#ifdef WOLFNANO_SERVER

/* Complete a TLS 1.3 PSK + ECDHE server handshake with a connecting client and
 * retain the application session in sess for wn_Send / wn_Recv / wn_Close. psk /
 * identity are the shared external PSK and its identity. scratch is a caller
 * buffer (>= 2048 bytes) used for record framing. */
WOLFNANO_API int wn_Accept_Psk_ex(wn_Session* sess, WC_RNG* rng,
                                  wn_IoSend ioSend, wn_IoRecv ioRecv, void* ioCtx,
                                  const byte* psk, word32 pskLen,
                                  const char* identity, byte* scratch,
                                  word32 scratchLen);

/* Handshake-only form: runs wn_Accept_Psk_ex on a stack session and wipes it. */
WOLFNANO_API int wn_Accept_Psk(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv,
                               void* ioCtx, const byte* psk, word32 pskLen,
                               const char* identity, byte* scratch,
                               word32 scratchLen);

#ifdef WOLFNANO_X509
/* Complete a TLS 1.3 certificate server handshake: present certDer (a leaf cert,
 * DER) and sign CertificateVerify under scheme with keyDer (private key, DER).
 * scheme is a WN_SIG_* TLS 1.3 signature scheme matching the key. scratch is a
 * caller buffer (>= 4096 bytes; larger for RSA/ML-DSA) for framing. */
WOLFNANO_API int wn_Accept_Cert_ex(wn_Session* sess, WC_RNG* rng,
                                   wn_IoSend ioSend, wn_IoRecv ioRecv,
                                   void* ioCtx, const byte* certDer,
                                   word32 certLen, const byte* keyDer,
                                   word32 keyLen, word16 scheme, byte* scratch,
                                   word32 scratchLen);

/* Handshake-only form: runs wn_Accept_Cert_ex on a stack session and wipes it. */
WOLFNANO_API int wn_Accept_Cert(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv,
                                void* ioCtx, const byte* certDer, word32 certLen,
                                const byte* keyDer, word32 keyLen, word16 scheme,
                                byte* scratch, word32 scratchLen);
#endif /* WOLFNANO_X509 */

#endif /* WOLFNANO_SERVER */

#endif /* WN_ACCEPT_H */
