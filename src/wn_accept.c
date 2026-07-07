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
#ifdef WOLFNANO_X509
#include "wn_servercert.h"
#endif
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>

#ifndef WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>   /* inline ForceZero / ConstantCompare */
#endif

#ifdef WOLFNANO_SERVER

#define WN_HS_CLIENT_HELLO   1
#define WN_HS_ENCRYPTED_EXT  8
#define WN_HS_FINISHED       20

/* Split-scratch reassembly needs room for two max ClientHello records; the
 * hybrid key_share (~1.2 KB) needs a larger floor than the ECDHE groups. */
#if WN_DEFAULT_PUB_SZ > 512
    #define WN_ACCEPT_SCRATCH_MIN 4096
#else
    #define WN_ACCEPT_SCRATCH_MIN 2048
#endif

/* RFC 8446 4.1.4: when the client offered our group but no matching key_share,
 * reply with HelloRetryRequest and read ClientHello2. Feeds the special
 * message_hash(CH1) + HRR into the transcript (4.4.1); leaves scratch = CH2 and
 * ch = the reparsed ClientHello2. No-op (returns success) if a key_share was
 * already usable. */
static int wn_Accept_MaybeHrr(wn_Transcript* tc, wn_IoSend ioSend,
                              wn_IoRecv ioRecv, void* ioCtx, byte* scratch,
                              word32 scratchLen, word32* chLen,
                              wn_ClientHello* ch)
{
    byte synth[4 + 32];
    byte hrr[128];
    word32 hrrLen, ch2Len, chHalf;
    int ret = WOLFNANO_SUCCESS;

    if (ch->haveKeyShare != 0) {
        return WOLFNANO_SUCCESS;
    }
    /* LCOV_EXCL_START: HRR needs a multi-group ClientHello (lead group != our
     * group, our group offered in supported_groups); the single-group
     * wn_Connect mock cannot produce one. Exercised end-to-end by the HRR
     * interop legs (interop_server_hrr.sh, OpenSSL leading a non-matching
     * key_share group) for both PSK and certificate servers. */
    synth[0] = 0xFE;                    /* handshake type message_hash */
    synth[1] = 0;
    synth[2] = 0;
    synth[3] = 32;
    ret = (wc_Sha256Hash(scratch, *chLen, synth + 4) != 0)
              ? WOLFNANO_E_CRYPTO : 0;
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(tc, synth, sizeof(synth));
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_HelloRetryRequest_Build(hrr, &hrrLen, sizeof(hrr),
                                         ch->sessionId, ch->sessionIdLen,
                                         ch->cipher, WN_DEFAULT_GROUP);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(tc, hrr, hrrLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_SendPlainRecord(ioSend, ioCtx, WN_REC_HANDSHAKE, hrr, hrrLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_SendCcs(ioSend, ioCtx);
    }
    if (ret == WOLFNANO_SUCCESS) {
        chHalf = scratchLen / 2;
        ret = wn_RecvHandshake(ioRecv, ioCtx, scratch, chHalf, scratch + chHalf,
                               scratchLen - chHalf, &ch2Len);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ClientHello_Parse(scratch, ch2Len, ch);
    }
    if ((ret == WOLFNANO_SUCCESS) && (ch->haveKeyShare == 0)) {
        ret = WOLFNANO_E_ILLEGAL_PARAM;   /* client ignored the retry */
    }
    if (ret == WOLFNANO_SUCCESS) {
        *chLen = ch2Len;
    }

    return ret;
    /* LCOV_EXCL_STOP */
}

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
    word32 recLen, chLen, chHalf, thLen, pubLen, ssLen, shLen, eeLen, flightLen, encLen;
    word32 idLen;
    byte rtype = 0, ctype = 0;
    byte sidLen;
    int ret = WOLFNANO_SUCCESS;
    int ksInit = 0, done = 0, hrrDone = 0;

    if ((sess == NULL) || (rng == NULL) || (ioSend == NULL) || (ioRecv == NULL) ||
        (psk == NULL) || (pskLen == 0) || (identity == NULL) ||
        (scratch == NULL) || (scratchLen < WN_ACCEPT_SCRATCH_MIN)) {
        return WOLFNANO_E_INVALID_ARG;
    }

    XMEMSET(zeros, 0, sizeof(zeros));
    idLen = (word32)XSTRLEN(identity);
    ret  = wn_Transcript_Init(&tc, WC_SHA256);
    ret |= (wc_Sha256Hash((const byte*)"", 0, emptyHash) != 0)
               ? WOLFNANO_E_CRYPTO : 0;
    ret |= (wc_RNG_GenerateBlock(rng, random32, 32) != 0)
               ? WOLFNANO_E_CRYPTO : 0;

    /* ----- receive + parse ClientHello (reassembled, RFC 8446 5.1) ----- */
    if (ret == WOLFNANO_SUCCESS) {
        chHalf = scratchLen / 2;
        ret = wn_RecvHandshake(ioRecv, ioCtx, scratch, chHalf, scratch + chHalf,
                               scratchLen - chHalf, &chLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ClientHello_Parse(scratch, chLen, &ch);
    }
    /* HelloRetryRequest when the client sent no usable key_share (RFC 8446
     * 4.1.4); after this ch is ClientHello2 and the transcript holds the
     * synthetic message_hash(CH1) + HRR. */
    if (ret == WOLFNANO_SUCCESS) {
        hrrDone = (ch.haveKeyShare == 0);
        ret = wn_Accept_MaybeHrr(&tc, ioSend, ioRecv, ioCtx, scratch, scratchLen,
                                 &chLen, &ch);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        ((ch.havePsk == 0) || (ch.pskIdentityLen != idLen) ||
         (XMEMCMP(ch.pskIdentity, identity, idLen) != 0))) {
        ret = WOLFNANO_E_ILLEGAL_PARAM;     /* no PSK, or offered identity is not ours */
    }

    /* ----- verify the PSK binder over the (HRR-aware) transcript ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret  = wn_Tls13_Extract(early, NULL, 0, psk, pskLen, WC_SHA256);
        ret |= wn_Tls13_DeriveSecret(binderKey, early, "ext binder", emptyHash,
                                     32, WC_SHA256);
    }
    if (ret == WOLFNANO_SUCCESS) {   /* transcript up to the binders (RFC 8446 4.2.11.2) */
        ret = wn_Transcript_Update(&tc, scratch, ch.binderTruncLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_GetHash(&tc, th, &thLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_FinishedMac(mac, binderKey, th, 32, WC_SHA256);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (ConstantCompare(mac, ch.binder, 32) != 0)) {
        ret = WOLFNANO_E_BAD_MAC;
    }
    if (ret == WOLFNANO_SUCCESS) {   /* append the binders to finish CH in the transcript */
        ret = wn_Transcript_Update(&tc, scratch + ch.binderTruncLen,
                                   chLen - ch.binderTruncLen);
    }

    /* ----- ECDHE, echo session id ----- */
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
                                   sidLen, ch.cipher, ch.group, srvPub, pubLen,
                                   0, 1);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, scratch, shLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_SendPlainRecord(ioSend, ioCtx, WN_REC_HANDSHAKE, scratch, shLen);
    }
    if ((ret == WOLFNANO_SUCCESS) && (hrrDone == 0)) {  /* one compat CCS: after HRR if it fired */
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
            ret = WOLFNANO_E_CRYPTO;  /* LCOV_EXCL_LINE: ioSend failure defensive path */
        }  /* LCOV_EXCL_LINE: defensive-branch close */
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
            ret = WOLFNANO_E_UNEXPECTED_MSG;  /* LCOV_EXCL_LINE: malformed client Finished record rejected (AEAD/format covered by rectest) */
        }  /* LCOV_EXCL_LINE: defensive-branch close */
        /* bound the plaintext to the destination before decrypting in place */
        if ((ret == WOLFNANO_SUCCESS) &&
            (recLen > sizeof(flight) + WN_RECORD_HEADER_SZ + WN_RECORD_TAG_SZ)) {
            ret = WOLFNANO_E_UNEXPECTED_MSG;  /* LCOV_EXCL_LINE: oversized client record guard */
        }  /* LCOV_EXCL_LINE: defensive-branch close */
        if (ret == WOLFNANO_SUCCESS) {
            ret = wn_Record_Unprotect(flight, &flightLen, &ctype, cKey, 16, cIv,
                                      0, scratch, recLen);
        }
        if ((ret == WOLFNANO_SUCCESS) &&
            ((ctype != WN_REC_HANDSHAKE) || (flightLen != (4 + 32)) ||
             (flight[0] != WN_HS_FINISHED))) {
            ret = WOLFNANO_E_UNEXPECTED_MSG;  /* LCOV_EXCL_LINE: malformed client Finished record rejected (covered by rectest) */
        }  /* LCOV_EXCL_LINE: defensive-branch close */
        if (ret == WOLFNANO_SUCCESS) {
            if (ConstantCompare(flight + 4, recvMac, 32) != 0) {
                ret = WOLFNANO_E_BAD_MAC;  /* LCOV_EXCL_LINE: client Finished MAC mismatch (FinishedMac covered by rfctest/hstest) */
            }  /* LCOV_EXCL_LINE: defensive-branch close */
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
    ForceZero(mac, sizeof(mac));
    ForceZero(recvMac, sizeof(recvMac));
    ForceZero(flight, sizeof(flight));
    if (ret != WOLFNANO_SUCCESS) {   /* never leave a half-open established session */
        ForceZero(sess, sizeof(*sess));
        ForceZero(scratch, scratchLen);   /* handshake plaintext lingered in scratch */
    }
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

#ifdef WOLFNANO_X509
int wn_Accept_Cert_ex(wn_Session* sess, WC_RNG* rng, wn_IoSend ioSend,
                      wn_IoRecv ioRecv, void* ioCtx, const byte* certDer,
                      word32 certLen, const byte* keyDer, word32 keyLen,
                      word16 scheme, byte* scratch, word32 scratchLen)
{
    wn_ClientHello ch;
    wn_KeyShare ks;
    wn_Transcript tc;
    byte random32[32], emptyHash[32], th[32], thCv[32], zeros[32];
    byte early[32], hs[32], cHs[32], sHs[32];
    byte cKey[16], cIv[12], sKey[16], sIv[12];
    byte srvPub[WN_KEYSHARE_MAX_PUB], ecdhe[WN_DEFAULT_SECRET_SZ];
    byte sid[32];
    byte mac[32], recvMac[32];
    byte* plain;
    byte* enc;
    word32 recLen, chLen, thLen, pubLen, ssLen, shLen, mLen, flightLen, encLen;
    word32 half, flightLen2;
    byte rtype = 0, ctype = 0;
    byte sidLen;
    int ret = WOLFNANO_SUCCESS;
    int ksInit = 0, done = 0, hrrDone = 0;

    if ((sess == NULL) || (rng == NULL) || (ioSend == NULL) ||
        (ioRecv == NULL) || (certDer == NULL) || (keyDer == NULL) ||
        (scratch == NULL) || (scratchLen < 4096)) {
        return WOLFNANO_E_INVALID_ARG;
    }

    half = scratchLen / 2;
    plain = scratch;
    enc = scratch + half;
    XMEMSET(zeros, 0, sizeof(zeros));
    ret  = wn_Transcript_Init(&tc, WC_SHA256);
    ret |= (wc_Sha256Hash((const byte*)"", 0, emptyHash) != 0)
               ? WOLFNANO_E_CRYPTO : 0;
    ret |= (wc_RNG_GenerateBlock(rng, random32, 32) != 0)
               ? WOLFNANO_E_CRYPTO : 0;

    /* ----- receive + parse ClientHello (no PSK; reassembled, RFC 8446 5.1) ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_RecvHandshake(ioRecv, ioCtx, plain, half, enc,
                               scratchLen - half, &chLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ClientHello_Parse(plain, chLen, &ch);
    }
    /* HelloRetryRequest when no usable key_share (RFC 8446 4.1.4); after this
     * plain holds ClientHello2 and the transcript holds message_hash(CH1)+HRR. */
    if (ret == WOLFNANO_SUCCESS) {
        hrrDone = (ch.haveKeyShare == 0);
        ret = wn_Accept_MaybeHrr(&tc, ioSend, ioRecv, ioCtx, scratch, scratchLen,
                                 &chLen, &ch);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wn_ClientHello_HasSigAlg(&ch, scheme) == 0)) {
        ret = WOLFNANO_E_ILLEGAL_PARAM;   /* client did not offer our scheme */
    }

    /* ----- transcript(CH), ECDHE, echo session id ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, plain, chLen);
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
            XMEMCPY(sid, ch.sessionId, sidLen);
        }
    }

    /* ----- ServerHello (no PSK) + compat ChangeCipherSpec ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ServerHello_Build(scratch, &shLen, scratchLen, random32, sid,
                                   sidLen, ch.cipher, ch.group, srvPub, pubLen,
                                   0, 0);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, scratch, shLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_SendPlainRecord(ioSend, ioCtx, WN_REC_HANDSHAKE, scratch, shLen);
    }
    if ((ret == WOLFNANO_SUCCESS) && (hrrDone == 0)) {  /* one compat CCS: after HRR if it fired */
        ret = wn_SendCcs(ioSend, ioCtx);
    }

    /* ----- handshake keys (early secret has no PSK: extract over zeros) ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_Extract(early, NULL, 0, zeros, 32, WC_SHA256);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret  = wn_Transcript_GetHash(&tc, th, &thLen);
        ret |= wn_DeriveHsKeys(hs, cHs, sHs, cKey, cIv, sKey, sIv, early, ecdhe,
                               ssLen, emptyHash, th);
    }

    /* ----- encrypted flight: EE || Certificate || CertVerify || Finished ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_EncExt_Build(plain, &mLen, half);
        flightLen = mLen;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, plain, mLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ServerCert_Build(plain + flightLen, &mLen, half - flightLen,
                                  certDer, certLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, plain + flightLen, mLen);
        flightLen += mLen;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_GetHash(&tc, thCv, &thLen);   /* CV signs through Cert */
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ServerCertVerify_Sign(plain + flightLen, &mLen,
                                       half - flightLen, scheme, keyDer, keyLen,
                                       thCv, thLen, rng);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, plain + flightLen, mLen);
        flightLen += mLen;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret  = wn_Transcript_GetHash(&tc, th, &thLen);
        ret |= wn_Tls13_FinishedMac(mac, sHs, th, 32, WC_SHA256);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        ((flightLen + 4 + 32 + WN_RECORD_HEADER_SZ + 1 + WN_RECORD_TAG_SZ)
            > half)) {
        ret = WOLFNANO_E_INVALID_ARG;      /* scratch too small for the flight */  /* LCOV_EXCL_LINE: flight buffer guard (oversized cert + undersized scratch) */
    }  /* LCOV_EXCL_LINE: defensive-branch close */
    if (ret == WOLFNANO_SUCCESS) {
        plain[flightLen] = WN_HS_FINISHED;
        plain[flightLen + 1] = 0;
        plain[flightLen + 2] = 0;
        plain[flightLen + 3] = 32;
        XMEMCPY(plain + flightLen + 4, mac, 32);
        flightLen2 = flightLen + 4 + 32;
        ret = wn_Transcript_Update(&tc, plain + flightLen, 4 + 32);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Record_Protect(enc, &encLen, sKey, 16, sIv, 0,
                                WN_REC_HANDSHAKE, plain, flightLen2);
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (ioSend(ioCtx, enc, encLen) != (int)encLen) {
            ret = WOLFNANO_E_CRYPTO;  /* LCOV_EXCL_LINE: ioSend failure defensive path */
        }  /* LCOV_EXCL_LINE: defensive-branch close */
    }

    /* ----- application secrets, expected client Finished MAC ----- */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_GetHash(&tc, th, &thLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_SessionEstablish(WN_ROLE_SERVER, sess, hs, emptyHash, zeros, th,
                                  ioSend, ioRecv, ioCtx, scratch, scratchLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_FinishedMac(recvMac, cHs, th, 32, WC_SHA256);
    }

    /* ----- receive + verify the client Finished (encrypted with cKey) ----- */
    while ((ret == WOLFNANO_SUCCESS) && (done == 0)) {
        ret = wn_RecvRecord(ioRecv, ioCtx, scratch, scratchLen, &rtype, &recLen);
        if ((ret == WOLFNANO_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER)) {
            continue;
        }
        if ((ret == WOLFNANO_SUCCESS) && (rtype != WN_REC_APPDATA)) {
            ret = WOLFNANO_E_UNEXPECTED_MSG;  /* LCOV_EXCL_LINE: malformed client Finished record rejected (covered by rectest) */
        }  /* LCOV_EXCL_LINE: defensive-branch close */
        /* bound the plaintext to the enc region before decrypting */
        if ((ret == WOLFNANO_SUCCESS) &&
            (recLen > half + WN_RECORD_HEADER_SZ + WN_RECORD_TAG_SZ)) {
            ret = WOLFNANO_E_UNEXPECTED_MSG;  /* LCOV_EXCL_LINE: oversized client record guard */
        }  /* LCOV_EXCL_LINE: defensive-branch close */
        if (ret == WOLFNANO_SUCCESS) {
            ret = wn_Record_Unprotect(enc, &flightLen, &ctype, cKey, 16, cIv,
                                      0, scratch, recLen);
        }
        if ((ret == WOLFNANO_SUCCESS) &&
            ((ctype != WN_REC_HANDSHAKE) || (flightLen != (4 + 32)) ||
             (enc[0] != WN_HS_FINISHED))) {
            ret = WOLFNANO_E_UNEXPECTED_MSG;  /* LCOV_EXCL_LINE: malformed client Finished record rejected (covered by rectest) */
        }  /* LCOV_EXCL_LINE: defensive-branch close */
        if (ret == WOLFNANO_SUCCESS) {
            if (ConstantCompare(enc + 4, recvMac, 32) != 0) {
                ret = WOLFNANO_E_BAD_MAC;  /* LCOV_EXCL_LINE: client Finished MAC mismatch (FinishedMac covered by rfctest/hstest) */
            }  /* LCOV_EXCL_LINE: defensive-branch close */
            done = 1;
        }
    }

    if (ksInit) {
        (void)wn_KeyShare_Free(&ks);
    }
    ForceZero(early, sizeof(early));
    ForceZero(hs, sizeof(hs));
    ForceZero(cHs, sizeof(cHs));
    ForceZero(sHs, sizeof(sHs));
    ForceZero(cKey, sizeof(cKey));
    ForceZero(cIv, sizeof(cIv));
    ForceZero(sKey, sizeof(sKey));
    ForceZero(sIv, sizeof(sIv));
    ForceZero(ecdhe, sizeof(ecdhe));
    ForceZero(mac, sizeof(mac));
    ForceZero(recvMac, sizeof(recvMac));
    ForceZero(thCv, sizeof(thCv));
    if (ret != WOLFNANO_SUCCESS) {   /* never leave a half-open established session */
        ForceZero(sess, sizeof(*sess));
        ForceZero(scratch, scratchLen);   /* Certificate/CV/Finished plaintext in scratch */
    }
    return ret;
}

int wn_Accept_Cert(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv, void* ioCtx,
                   const byte* certDer, word32 certLen, const byte* keyDer,
                   word32 keyLen, word16 scheme, byte* scratch,
                   word32 scratchLen)
{
    wn_Session sess;
    int ret;

    XMEMSET(&sess, 0, sizeof(sess));
    ret = wn_Accept_Cert_ex(&sess, rng, ioSend, ioRecv, ioCtx, certDer, certLen,
                            keyDer, keyLen, scheme, scratch, scratchLen);
    ForceZero(&sess, sizeof(sess));
    return ret;
}
#endif /* WOLFNANO_X509 */

#endif /* WOLFNANO_SERVER */
