/* wn_transcript.h
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
 * TLS 1.3 handshake transcript hash (RFC 8446 section 4.4.1). Running hash over
 * handshake messages with a non-destructive interim digest. Caller holds the
 * context; no allocation.
 */

#ifndef WN_TRANSCRIPT_H
#define WN_TRANSCRIPT_H

#include "wolfnano.h"
#include "wolfnano_crypto.h"

typedef struct wn_Transcript {
    union {
        wc_Sha256 s256;
#ifdef WOLFSSL_SHA384
        wc_Sha384 s384;
#endif
    } h;
    int digest;
} wn_Transcript;

/* Begin a transcript over the given digest (WC_SHA256 or WC_SHA384). */
WOLFNANO_API int wn_Transcript_Init(wn_Transcript* t, int digest);

/* Append a handshake message to the transcript. */
WOLFNANO_API int wn_Transcript_Update(wn_Transcript* t, const byte* msg,
                                      word32 msgLen);

/* Current Transcript-Hash without ending the transcript. out is Hash.length
 * bytes; outLen receives that length. */
WOLFNANO_API int wn_Transcript_GetHash(wn_Transcript* t, byte* out,
                                       word32* outLen);

/* Release the transcript context. */
WOLFNANO_API int wn_Transcript_Free(wn_Transcript* t);

#endif /* WN_TRANSCRIPT_H */
