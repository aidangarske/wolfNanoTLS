/* wn_accept.c
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
 * TLS 1.3 external-PSK + ECDHE server handshake (RFC 8446). Receives ClientHello
 * (verifying the PSK binder), sends ServerHello + the encrypted
 * EncryptedExtensions + Finished flight, then verifies the client Finished.
 * Logic ported from wolfSSL tls13.c server path; crypto via wc_*; no allocation.
 */

#include "wn_accept.h"
#include "wn_msg.h"
#include "wn_keyshare.h"
#include "wn_keyschedule.h"
#include "wn_transcript.h"
#include "wn_record.h"
#include "wn_clienthello.h"
#include "wn_serverhello.h"
#include "wn_handshake.h"
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>

#ifndef WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>   /* inline ForceZero / ConstantCompare */
#endif

#define WN_HS_CLIENT_HELLO   1
#define WN_HS_ENCRYPTED_EXT  8
#define WN_HS_FINISHED       20

int wn_Accept_Psk_ex(wn_Session* sess, WC_RNG* rng, wn_IoSend ioSend,
                     wn_IoRecv ioRecv, void* ioCtx, const byte* psk,
                     word32 pskLen, const char* identity, byte* scratch,
                     word32 scratchLen)
{
    wn_ClientHello ch;
    wn_KeyShare ks;
    wn_Transcript tc;
    byte random32[32], emptyHash[32], th[32], zeros[32];
    byte early[32], binderKey[32], hs[32], cHs[32], sHs[32];
    byte cKey[16], cIv[12], sKey[16], sIv[12];
    byte srvPub[WN_KEYSHARE_MAX_PUB], ecdhe[WN_DEFAULT_SECRET_SZ];
    byte sid[32];
    byte mac[32], recvMac[32];
    byte flight[128];
    word32 recLen, chLen, thLen, pubLen, ssLen, shLen, eeLen, flightLen, encLen;
    word32 idLen;
    byte rtype = 0, ctype = 0;
    byte sidLen;
    int ret = WOLFNANO_SUCCESS;
    int ksInit = 0, done = 0;

    if ((sess == NULL) || (rng == NULL) || (ioSend == NULL) || (ioRecv == NULL) ||
        (psk == NULL) || (identity == NULL) || (scratch == NULL) ||
        (scratchLen < 2048)) {
        return WOLFNANO_E_INVALID_ARG;
    }

    XMEMSET(zeros, 0, sizeof(zeros));
    idLen = (word32)XSTRLEN(identity);
    ret  = wn_Transcript_Init(&tc, WC_SHA256);
    ret |= (wc_Sha256Hash((const byte*)"", 0, emptyHash) != 0)
               ? WOLFNANO_E_CRYPTO : 0;
    ret |= (wc_RNG_GenerateBlock(rng, random32, 32) != 0)
               ? WOLFNANO_E_CRYPTO : 0;

    /* ----- receive + parse ClientHello ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_RecvRecord(ioRecv, ioCtx, scratch, scratchLen, &rtype, &recLen);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        ((rtype != WN_REC_HANDSHAKE) || (recLen <= WN_RECORD_HEADER_SZ))) {
        ret = WOLFNANO_E_UNEXPECTED_MSG;
    }
    if (ret == WOLFNANO_SUCCESS) {
        chLen = recLen - WN_RECORD_HEADER_SZ;
        ret = wn_ClientHello_Parse(scratch + WN_RECORD_HEADER_SZ, chLen, &ch);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        ((ch.pskIdentityLen != idLen) ||
         (XMEMCMP(ch.pskIdentity, identity, idLen) != 0))) {
        ret = WOLFNANO_E_ILLEGAL_PARAM;     /* offered identity is not ours */
    }

    /* ----- verify the PSK binder over the truncated ClientHello ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret  = wn_Tls13_Extract(early, NULL, 0, psk, pskLen, WC_SHA256);
        ret |= wn_Tls13_DeriveSecret(binderKey, early, "ext binder", emptyHash,
                                     32, WC_SHA256);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = (wc_Sha256Hash(scratch + WN_RECORD_HEADER_SZ, ch.binderTruncLen,
                             th) != 0) ? WOLFNANO_E_CRYPTO : 0;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_FinishedMac(mac, binderKey, th, 32, WC_SHA256);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (ConstantCompare(mac, ch.binder, 32) != 0)) {
        ret = WOLFNANO_E_BAD_MAC;
    }

    /* ----- transcript(CH), ECDHE, echo session id ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, scratch + WN_RECORD_HEADER_SZ, chLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_KeyShare_Init(&ks, ch.group);
        if (ret == WOLFNANO_SUCCESS) {
            ksInit = 1;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_KeyShare_ServerShare(&ks, rng, ch.keyShare, ch.keyShareLen,
                                      srvPub, &pubLen, ecdhe, &ssLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        sidLen = ch.sessionIdLen;
        if (sidLen > 0) {
            XMEMCPY(sid, ch.sessionId, sidLen);  /* copy before scratch reuse */
        }
    }

    /* ----- ServerHello (+ compat ChangeCipherSpec) ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ServerHello_Build(scratch, &shLen, scratchLen, random32, sid,
                                   sidLen, ch.cipher, ch.group, srvPub, pubLen, 0);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, scratch, shLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_SendPlainRecord(ioSend, ioCtx, WN_REC_HANDSHAKE, scratch, shLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_SendCcs(ioSend, ioCtx);
    }

    /* ----- handshake key schedule (server writes sHs, reads cHs) ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret  = wn_Transcript_GetHash(&tc, th, &thLen);
        ret |= wn_DeriveHsKeys(hs, cHs, sHs, cKey, cIv, sKey, sIv, early, ecdhe,
                               ssLen, emptyHash, th);
    }

    /* ----- EncryptedExtensions + server Finished, encrypted with sKey ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_EncExt_Build(flight, &eeLen, sizeof(flight));
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, flight, eeLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret  = wn_Transcript_GetHash(&tc, th, &thLen);
        ret |= wn_Tls13_FinishedMac(mac, sHs, th, 32, WC_SHA256);
    }
    if (ret == WOLFNANO_SUCCESS) {
        flight[eeLen] = WN_HS_FINISHED;
        flight[eeLen + 1] = 0;
        flight[eeLen + 2] = 0;
        flight[eeLen + 3] = 32;
        XMEMCPY(flight + eeLen + 4, mac, 32);
        flightLen = eeLen + 4 + 32;
        ret = wn_Transcript_Update(&tc, flight + eeLen, 4 + 32);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Record_Protect(scratch, &encLen, sKey, 16, sIv, 0,
                                WN_REC_HANDSHAKE, flight, flightLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (ioSend(ioCtx, scratch, encLen) != (int)encLen) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    /* ----- application traffic secrets, transcript through server Finished ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_GetHash(&tc, th, &thLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_SessionEstablish(WN_ROLE_SERVER, sess, hs, emptyHash, zeros, th,
                                  ioSend, ioRecv, ioCtx, scratch, scratchLen);
    }
    /* expected client Finished MAC over the same transcript */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_FinishedMac(recvMac, cHs, th, 32, WC_SHA256);
    }

    /* ----- receive + verify the client Finished (encrypted with cKey) ----- */
    while ((ret == WOLFNANO_SUCCESS) && (done == 0)) {
        ret = wn_RecvRecord(ioRecv, ioCtx, scratch, scratchLen, &rtype, &recLen);
        if ((ret == WOLFNANO_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER)) {
            continue;                       /* skip the client compat CCS */
        }
        if ((ret == WOLFNANO_SUCCESS) && (rtype != WN_REC_APPDATA)) {
            ret = WOLFNANO_E_UNEXPECTED_MSG;
        }
        if (ret == WOLFNANO_SUCCESS) {
            ret = wn_Record_Unprotect(flight, &flightLen, &ctype, cKey, 16, cIv,
                                      0, scratch, recLen);
        }
        if ((ret == WOLFNANO_SUCCESS) &&
            ((ctype != WN_REC_HANDSHAKE) || (flightLen != (4 + 32)) ||
             (flight[0] != WN_HS_FINISHED))) {
            ret = WOLFNANO_E_UNEXPECTED_MSG;
        }
        if (ret == WOLFNANO_SUCCESS) {
            if (ConstantCompare(flight + 4, recvMac, 32) != 0) {
                ret = WOLFNANO_E_BAD_MAC;
            }
            done = 1;
        }
    }

    if (ksInit) {
        (void)wn_KeyShare_Free(&ks);
    }
    ForceZero(early, sizeof(early));
    ForceZero(binderKey, sizeof(binderKey));
    ForceZero(hs, sizeof(hs));
    ForceZero(cHs, sizeof(cHs));
    ForceZero(sHs, sizeof(sHs));
    ForceZero(cKey, sizeof(cKey));
    ForceZero(cIv, sizeof(cIv));
    ForceZero(sKey, sizeof(sKey));
    ForceZero(sIv, sizeof(sIv));
    ForceZero(ecdhe, sizeof(ecdhe));
    return ret;
}

int wn_Accept_Psk(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv, void* ioCtx,
                  const byte* psk, word32 pskLen, const char* identity,
                  byte* scratch, word32 scratchLen)
{
    wn_Session sess;
    int ret;

    XMEMSET(&sess, 0, sizeof(sess));
    ret = wn_Accept_Psk_ex(&sess, rng, ioSend, ioRecv, ioCtx, psk, pskLen,
                           identity, scratch, scratchLen);
    ForceZero(&sess, sizeof(sess));
    return ret;
}
