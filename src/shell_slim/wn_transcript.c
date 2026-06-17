/* wn_transcript.c
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
 * TLS 1.3 handshake transcript hash over the wc_* seam. Incremental SHA-256 /
 * SHA-384 with a non-destructive interim digest (wc_ShaXxxGetHash).
 */

#include "wn_transcript.h"

int wn_Transcript_Init(wn_Transcript* t, int digest)
{
    int ret = WOLFNANO_SUCCESS;

    if (t == NULL) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        t->digest = digest;
        if (digest == WC_SHA256) {
            ret = wc_InitSha256(&t->h.s256);
        }
        else if (digest == WC_SHA384) {
            ret = wc_InitSha384(&t->h.s384);
        }
        else {
            ret = WOLFNANO_E_UNSUPPORTED;
        }
        if ((ret != 0) && (ret != WOLFNANO_E_UNSUPPORTED)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    return ret;
}

int wn_Transcript_Update(wn_Transcript* t, const byte* msg, word32 msgLen)
{
    int ret = WOLFNANO_SUCCESS;

    if ((t == NULL) || ((msg == NULL) && (msgLen != 0))) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        if (t->digest == WC_SHA256) {
            ret = wc_Sha256Update(&t->h.s256, msg, msgLen);
        }
        else if (t->digest == WC_SHA384) {
            ret = wc_Sha384Update(&t->h.s384, msg, msgLen);
        }
        else {
            ret = WOLFNANO_E_UNSUPPORTED;
        }
        if ((ret != 0) && (ret != WOLFNANO_E_UNSUPPORTED)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    return ret;
}

int wn_Transcript_GetHash(wn_Transcript* t, byte* out, word32* outLen)
{
    int ret = WOLFNANO_SUCCESS;

    if ((t == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        if (t->digest == WC_SHA256) {
            ret = wc_Sha256GetHash(&t->h.s256, out);
            *outLen = WC_SHA256_DIGEST_SIZE;
        }
        else if (t->digest == WC_SHA384) {
            ret = wc_Sha384GetHash(&t->h.s384, out);
            *outLen = WC_SHA384_DIGEST_SIZE;
        }
        else {
            ret = WOLFNANO_E_UNSUPPORTED;
        }
        if ((ret != 0) && (ret != WOLFNANO_E_UNSUPPORTED)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    return ret;
}

int wn_Transcript_Free(wn_Transcript* t)
{
    int ret = WOLFNANO_SUCCESS;

    if (t == NULL) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        if (t->digest == WC_SHA256) {
            wc_Sha256Free(&t->h.s256);
        }
        else if (t->digest == WC_SHA384) {
            wc_Sha384Free(&t->h.s384);
        }
    }

    return ret;
}
