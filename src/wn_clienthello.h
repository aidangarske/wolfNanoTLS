/* wn_clienthello.h
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
 * TLS 1.3 ClientHello encoder (RFC 8446 section 4.1.2). Offers
 * TLS_AES_128_GCM_SHA256, the configured (EC)DHE group, and the signature
 * algorithms wolfNanoTLS supports. Caller-provided output; no allocation.
 */

#ifndef WN_CLIENTHELLO_H
#define WN_CLIENTHELLO_H

#include "wolfnano.h"

#define WN_CIPHER_AES_128_GCM_SHA256 0x1301

/* Encode a ClientHello handshake message (type 1 + length + body) into out.
 * random32 is the 32-byte ClientHello.random; sessionId/sessionIdLen is the
 * legacy_session_id (0..32); pub/pubLen is the wire-format (EC)DHE key share. */
WOLFNANO_API int wn_ClientHello_Build(byte* out, word32* outLen, word32 outCap,
                                      const byte* random32,
                                      const byte* sessionId, word32 sessionIdLen,
                                      const byte* pub, word32 pubLen);

/* As wn_ClientHello_Build, plus a server_name (SNI, RFC 6066) extension when
 * serverName is non-NULL (host_name type). serverName is a NUL-terminated DNS
 * name; pass NULL to omit SNI. */
WOLFNANO_API int wn_ClientHello_Build_ex(byte* out, word32* outLen,
                                         word32 outCap, const byte* random32,
                                         const byte* sessionId,
                                         word32 sessionIdLen, const byte* pub,
                                         word32 pubLen, const char* serverName);

#ifdef WOLFNANO_SERVER
/* Parsed ClientHello for the server (RFC 8446 4.1.2). Pointers reference the
 * caller's input message. binderTruncLen is the message offset where the PSK
 * binders section begins (the transcript boundary the binder is computed over). */
typedef struct wn_ClientHello {
    const byte* sessionId;      /* legacy_session_id (echo in ServerHello) */
    const byte* keyShare;       /* client (EC)DHE public for the selected group */
    const byte* pskIdentity;    /* first offered PSK identity */
    const byte* binder;         /* PSK binder for that identity */
    word32 keyShareLen;
    word32 pskIdentityLen;
    word32 binderLen;
    word32 binderTruncLen;
    word16 cipher;              /* selected cipher suite */
    word16 group;              /* selected key_share group */
    byte sessionIdLen;
    byte haveKeyShare;
    byte havePsk;
} wn_ClientHello;

/* Decode a ClientHello handshake message (type 1 + length + body). Selects the
 * cipher suite and key_share group wolfNanoTLS supports; fails closed. */
WOLFNANO_LOCAL int wn_ClientHello_Parse(const byte* msg, word32 msgLen,
                                        wn_ClientHello* out);
#endif /* WOLFNANO_SERVER */

#endif /* WN_CLIENTHELLO_H */
