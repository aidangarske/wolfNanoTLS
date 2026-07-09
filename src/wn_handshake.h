/* wn_handshake.h
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
 * Shared TLS 1.3 handshake helpers used by both the client (wn_connect.c) and
 * the server (wn_accept.c): plaintext record send, ChangeCipherSpec, the
 * handshake key schedule, EncryptedExtensions validation, and role-aware
 * application-key session establishment. Logic ported from wolfSSL tls13.c; all
 * crypto via the wc_* seam; no allocation.
 */

#ifndef WN_HANDSHAKE_H
#define WN_HANDSHAKE_H

#include "wn_session.h"

/* Handshake role: selects application-key polarity in wn_SessionEstablish. */
#define WN_ROLE_CLIENT 0
#define WN_ROLE_SERVER 1

/* Send one plaintext TLS record (5-byte header + body) via the IO callback. */
WOLFNANO_LOCAL int wn_SendPlainRecord(wn_IoSend send, void* ctx, byte type,
                                      const byte* body, word32 bodyLen);

/* Send the TLS 1.3 middlebox-compatibility ChangeCipherSpec (RFC 8446 D.4). */
WOLFNANO_LOCAL int wn_SendCcs(wn_IoSend send, void* ctx);

/* Read plaintext handshake records (skipping compat ChangeCipherSpec) and
 * reassemble exactly one complete handshake message into acc (RFC 8446 5.1: a
 * message may span records). Records are read into the caller's tmp buffer;
 * msgLen receives the reassembled length. */
WOLFNANO_LOCAL int wn_RecvHandshake(wn_IoRecv ioRecv, void* ioCtx, byte* acc,
                                    word32 accCap, byte* tmp, word32 tmpCap,
                                    word32* msgLen);

/* RFC 8446 7.1: handshake secret, c/s hs traffic, and both record key/iv pairs.
 * early differs per path (PSK vs zeros). Direction-neutral: the caller picks
 * which side (c or s) is its write vs read. */
WOLFNANO_LOCAL int wn_DeriveHsKeys(byte* hs, byte* cHs, byte* sHs, byte* cKey,
                                   byte* cIv, byte* sKey, byte* sIv,
                                   const byte* early, const byte* ecdhe,
                                   word32 ecdheLen, const byte* emptyHash,
                                   const byte* th);

/* RFC 8446 7.1: master secret, c/s ap traffic, app key/iv, then populate the
 * session for wn_Send / wn_Recv. role selects polarity: a client writes with
 * "c ap traffic" and reads "s ap traffic"; a server is the mirror. */
WOLFNANO_LOCAL int wn_SessionEstablish(int role, wn_Session* sess,
                                       const byte* hs, const byte* emptyHash,
                                       const byte* zeros, const byte* th,
                                       wn_IoSend ioSend, wn_IoRecv ioRecv,
                                       void* ioCtx, byte* scratch,
                                       word32 scratchLen);

#endif /* WN_HANDSHAKE_H */
