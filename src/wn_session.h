/* wn_session.h
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
 * TLS 1.3 application-data session (RFC 8446 section 4.6 / 5.2). Holds the
 * application traffic keys retained from the handshake and drives record-layer
 * send/receive over the wc_* seam. Post-handshake NewSessionTicket is ignored
 * and KeyUpdate is handled transparently. Caller-provided buffers; no alloc.
 */

#ifndef WN_SESSION_H
#define WN_SESSION_H

#include "wolfnano.h"

#define WN_SECRET_SZ   32   /* SHA-256 traffic secret */
#define WN_AEAD_KEY_SZ 16   /* AES-128-GCM key */
#define WN_AEAD_IV_SZ  12   /* AES-128-GCM iv */

#define WN_SESS_ESTABLISHED 1
#define WN_SESS_CLOSED      2

typedef struct wn_Session {
    wn_IoSend ioSend;
    wn_IoRecv ioRecv;
    void*     ioCtx;
    byte*     scratch;                   /* caller buffer for record framing */
    word32    scratchLen;
    byte      cAppSecret[WN_SECRET_SZ];  /* our application traffic secret */
    byte      sAppSecret[WN_SECRET_SZ];  /* peer application traffic secret */
    byte      cKey[WN_AEAD_KEY_SZ];
    byte      cIv[WN_AEAD_IV_SZ];
    byte      sKey[WN_AEAD_KEY_SZ];
    byte      sIv[WN_AEAD_IV_SZ];
    word64    cSeq;                       /* our write record counter */
    word64    sSeq;                       /* peer read record counter */
    int       digest;
    int       flags;
} wn_Session;

/* A wn_Session is single-threaded: serialize wn_Send/wn_Recv/wn_Close on one
 * session (no internal locking, by design - zero allocation, embedded). */

/* Encrypt and send one application_data record. Returns WOLFNANO_SUCCESS. */
WOLFNANO_API int wn_Send(wn_Session* s, const byte* data, word32 len);

/* Receive one application_data record into out (up to outCap bytes), setting
 * *outLen. Transparently skips NewSessionTicket and processes KeyUpdate.
 * Returns WOLFNANO_E_CLOSED with *outLen 0 if the peer sent close_notify. */
WOLFNANO_API int wn_Recv(wn_Session* s, byte* out, word32 outCap,
                         word32* outLen);

/* Send an encrypted close_notify and wipe all session key material. */
WOLFNANO_API int wn_Close(wn_Session* s);

#endif /* WN_SESSION_H */
