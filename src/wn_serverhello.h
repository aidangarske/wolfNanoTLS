/* wn_serverhello.h
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
 * TLS 1.3 ServerHello parser (RFC 8446 section 4.1.3). Extracts the negotiated
 * cipher suite, the server key_share, the selected version, and (for PSK) the
 * selected pre_shared_key identity. Pointers reference the caller's input.
 */

#ifndef WN_SERVERHELLO_H
#define WN_SERVERHELLO_H

#include "wolfnano.h"

typedef struct wn_ServerHello {
    const byte* random;        /* 32 bytes into the input */
    const byte* keyShare;      /* server key_share key data */
    const byte* sessionId;     /* legacy_session_id_echo into the input */
    word32 keyShareLen;
    word16 cipher;
    word16 group;              /* selected key_share group */
    word16 version;            /* selected supported_versions value */
    int pskSelected;           /* selected PSK identity index, or -1 */
    int isHelloRetry;          /* random matched the HRR sentinel */
    byte sessionIdLen;         /* legacy_session_id_echo length */
} wn_ServerHello;

WOLFNANO_API int wn_ServerHello_Parse(const byte* msg, word32 msgLen,
                                      wn_ServerHello* out);

#ifdef WOLFNANO_SERVER
/* Encode a ServerHello (type 2 + length + body) into out: negotiated cipher,
 * echoed session id, server key_share, and, when includePsk is nonzero, the
 * selected pre_shared_key identity index (omitted for certificate auth). */
WOLFNANO_LOCAL int wn_ServerHello_Build(byte* out, word32* outLen, word32 outCap,
                                        const byte* random32,
                                        const byte* sessionId, byte sessionIdLen,
                                        word16 cipher, word16 group,
                                        const byte* srvPub, word32 srvPubLen,
                                        word16 pskIdentity, int includePsk);

/* Encode an empty EncryptedExtensions (type 8 + length + empty vector). */
WOLFNANO_LOCAL int wn_EncExt_Build(byte* out, word32* outLen, word32 outCap);
#endif /* WOLFNANO_SERVER */

#endif /* WN_SERVERHELLO_H */
