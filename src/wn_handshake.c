/* wn_handshake.c
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
 * Shared TLS 1.3 handshake helpers for the client and server shells. Logic
 * ported from wolfSSL tls13.c; all crypto via the wc_* seam; no allocation.
 */

#include "wn_handshake.h"
#include "wn_msg.h"
#include "wn_keyschedule.h"
#include "wn_record.h"
#include <wolfssl/wolfcrypt/hash.h>

#ifndef WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>   /* inline ForceZero */
#endif

int wn_SendPlainRecord(wn_IoSend send, void* ctx, byte type, const byte* body,
                       word32 bodyLen)
{
    byte hdr[5];
    int ret = WOLFNANO_SUCCESS;
    int r;

    hdr[0] = type;
    hdr[1] = 0x03;
    hdr[2] = 0x03;
    hdr[3] = (byte)(bodyLen >> 8);
    hdr[4] = (byte)(bodyLen & 0xff);

    r = send(ctx, hdr, 5);
    if (r != 5) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (ret == WOLFNANO_SUCCESS) {
        r = send(ctx, body, bodyLen);
        if ((word32)r != bodyLen) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    return ret;
}

int wn_SendCcs(wn_IoSend send, void* ctx)
{
    static const byte ccs = 0x01;

    return wn_SendPlainRecord(send, ctx, WN_REC_CHANGE_CIPHER, &ccs, 1);
}

int wn_DeriveHsKeys(byte* hs, byte* cHs, byte* sHs, byte* cKey, byte* cIv,
                    byte* sKey, byte* sIv, const byte* early, const byte* ecdhe,
                    word32 ecdheLen, const byte* emptyHash, const byte* th)
{
    byte derived[32];
    int ret;

    ret  = wn_Tls13_DeriveSecret(derived, early, "derived", emptyHash, 32,
                                 WC_SHA256);
    ret |= wn_Tls13_Extract(hs, derived, 32, ecdhe, ecdheLen, WC_SHA256);
    ret |= wn_Tls13_DeriveSecret(cHs, hs, "c hs traffic", th, 32, WC_SHA256);
    ret |= wn_Tls13_DeriveSecret(sHs, hs, "s hs traffic", th, 32, WC_SHA256);
    ret |= wn_Tls13_ExpandLabel(cKey, 16, cHs, "key", NULL, 0, WC_SHA256);
    ret |= wn_Tls13_ExpandLabel(cIv, 12, cHs, "iv", NULL, 0, WC_SHA256);
    ret |= wn_Tls13_ExpandLabel(sKey, 16, sHs, "key", NULL, 0, WC_SHA256);
    ret |= wn_Tls13_ExpandLabel(sIv, 12, sHs, "iv", NULL, 0, WC_SHA256);

    ForceZero(derived, sizeof(derived));
    return ret;
}

int wn_SessionEstablish(int role, wn_Session* sess, const byte* hs,
                        const byte* emptyHash, const byte* zeros,
                        const byte* th, wn_IoSend ioSend, wn_IoRecv ioRecv,
                        void* ioCtx, byte* scratch, word32 scratchLen)
{
    byte derived[32];
    byte master[WN_SECRET_SZ];
    const char* ourLabel;
    const char* peerLabel;
    int ret;

    /* Our write secret is our own side; a server writes with "s ap traffic". */
    if (role == WN_ROLE_SERVER) {
        ourLabel  = "s ap traffic";
        peerLabel = "c ap traffic";
    }
    else {
        ourLabel  = "c ap traffic";
        peerLabel = "s ap traffic";
    }

    ret  = wn_Tls13_DeriveSecret(derived, hs, "derived", emptyHash, 32,
                                 WC_SHA256);
    ret |= wn_Tls13_Extract(master, derived, 32, zeros, 32, WC_SHA256);
    ret |= wn_Tls13_DeriveSecret(sess->cAppSecret, master, ourLabel, th, 32,
                                 WC_SHA256);
    ret |= wn_Tls13_DeriveSecret(sess->sAppSecret, master, peerLabel, th, 32,
                                 WC_SHA256);
    ret |= wn_Tls13_ExpandLabel(sess->cKey, WN_AEAD_KEY_SZ, sess->cAppSecret,
                                "key", NULL, 0, WC_SHA256);
    ret |= wn_Tls13_ExpandLabel(sess->cIv, WN_AEAD_IV_SZ, sess->cAppSecret,
                                "iv", NULL, 0, WC_SHA256);
    ret |= wn_Tls13_ExpandLabel(sess->sKey, WN_AEAD_KEY_SZ, sess->sAppSecret,
                                "key", NULL, 0, WC_SHA256);
    ret |= wn_Tls13_ExpandLabel(sess->sIv, WN_AEAD_IV_SZ, sess->sAppSecret,
                                "iv", NULL, 0, WC_SHA256);

    if (ret == WOLFNANO_SUCCESS) {
        sess->ioSend = ioSend;
        sess->ioRecv = ioRecv;
        sess->ioCtx = ioCtx;
        sess->scratch = scratch;
        sess->scratchLen = scratchLen;
        sess->cSeq = 0;
        sess->sSeq = 0;
        sess->digest = WC_SHA256;
        sess->flags = WN_SESS_ESTABLISHED;
    }

    ForceZero(derived, sizeof(derived));
    ForceZero(master, sizeof(master));
    return ret;
}
