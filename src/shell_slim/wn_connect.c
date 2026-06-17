/* wn_connect.c
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
 * TLS 1.3 external-PSK + ECDHE client handshake (RFC 8446). Drives ClientHello
 * (with PSK binder), ServerHello, the encrypted EncryptedExtensions + Finished
 * flight, server Finished verification, and client Finished. Logic ported from
 * wolfSSL tls13.c; transport via I/O callbacks; no allocation.
 */

#include "wn_connect.h"
#include "wn_msg.h"
#include "wn_keyschedule.h"
#include "wn_transcript.h"
#include "wn_record.h"
#include "wn_keyshare.h"
#include "wn_serverhello.h"

#ifndef WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>   /* inline ForceZero / ConstantCompare */
#endif

#define WN_HS_FINISHED       20
#define WN_HS_ENCRYPTED_EXT  8
#define WN_REC_HANDSHAKE     22
#define WN_REC_APPDATA       23
#define WN_REC_CHANGE_CIPHER 20
#define WN_REC_ALERT         21

static int io_recv_exact(wn_IoRecv recv, void* ctx, byte* buf, word32 n)
{
    int ret = WOLFNANOTLS_SUCCESS;
    word32 got = 0;
    int r;

    while ((got < n) && (ret == WOLFNANOTLS_SUCCESS)) {
        r = recv(ctx, buf + got, n - got);
        if (r <= 0) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
        else {
            got += (word32)r;
        }
    }

    return ret;
}

/* Read one TLS record: 5-byte header then the fragment. */
static int recv_record(wn_IoRecv recv, void* ctx, byte* rec, word32 cap,
                       byte* type, word32* recLen)
{
    word32 frag;
    int ret;

    ret = io_recv_exact(recv, ctx, rec, 5);
    if (ret == WOLFNANOTLS_SUCCESS) {
        *type = rec[0];
        frag = ((word32)rec[3] << 8) | rec[4];
        if ((frag == 0) || ((frag + 5) > cap)) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = io_recv_exact(recv, ctx, rec + 5, frag);
        *recLen = frag + 5;
    }

    return ret;
}

static int send_plain_record(wn_IoSend send, void* ctx, byte type,
                             const byte* body, word32 bodyLen)
{
    byte hdr[5];
    int ret = WOLFNANOTLS_SUCCESS;
    int r;

    hdr[0] = type;
    hdr[1] = 0x03;
    hdr[2] = 0x03;
    hdr[3] = (byte)(bodyLen >> 8);
    hdr[4] = (byte)(bodyLen & 0xff);

    r = send(ctx, hdr, 5);
    if (r != 5) {
        ret = WOLFNANOTLS_E_CRYPTO;
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        r = send(ctx, body, bodyLen);
        if ((word32)r != bodyLen) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }

    return ret;
}

/* Build a PSK+ECDHE ClientHello body+header into w. Records the offset to hash
 * for the binder (truncOff) and where the 32-byte binder is written. */
static void build_client_hello(wn_Writer* w, const byte* random32,
                               const byte* sid, const byte* cliPub,
                               const char* identity, word32 idLen,
                               word32* truncOff, word32* binderOff)
{
    word32 hsLen, extLen, pskLen, idsLen;
    int i;

    wn_Write_U8(w, 1);                          /* ClientHello */
    hsLen = wn_Write_LenStart(w, 3);

    wn_Write_U16(w, 0x0303);
    wn_Write_Bytes(w, random32, 32);
    wn_Write_U8(w, 32);
    wn_Write_Bytes(w, sid, 32);
    wn_Write_U16(w, 2);
    wn_Write_U16(w, 0x1301);
    wn_Write_U8(w, 1);
    wn_Write_U8(w, 0);

    extLen = wn_Write_LenStart(w, 2);

    wn_Write_U16(w, 43);                        /* supported_versions */
    wn_Write_U16(w, 3);
    wn_Write_U8(w, 2);
    wn_Write_U16(w, 0x0304);

    wn_Write_U16(w, 10);                        /* supported_groups */
    wn_Write_U16(w, 4);
    wn_Write_U16(w, 2);
    wn_Write_U16(w, 0x001d);

    wn_Write_U16(w, 13);                        /* signature_algorithms */
    wn_Write_U16(w, 6);
    wn_Write_U16(w, 4);
    wn_Write_U16(w, 0x0807);
    wn_Write_U16(w, 0x0403);

    wn_Write_U16(w, 51);                        /* key_share */
    wn_Write_U16(w, 38);
    wn_Write_U16(w, 36);
    wn_Write_U16(w, 0x001d);
    wn_Write_U16(w, 32);
    wn_Write_Bytes(w, cliPub, 32);

    wn_Write_U16(w, 45);                        /* psk_key_exchange_modes */
    wn_Write_U16(w, 2);
    wn_Write_U8(w, 1);
    wn_Write_U8(w, 1);                          /* psk_dhe_ke */

    wn_Write_U16(w, 41);                        /* pre_shared_key (last) */
    pskLen = wn_Write_LenStart(w, 2);
    idsLen = wn_Write_LenStart(w, 2);           /* identities */
    wn_Write_U16(w, (word16)idLen);
    wn_Write_Bytes(w, (const byte*)identity, idLen);
    wn_Write_U16(w, 0);                         /* obfuscated_ticket_age hi */
    wn_Write_U16(w, 0);                         /* obfuscated_ticket_age lo */
    wn_Write_LenEnd(w, idsLen, 2);

    *truncOff = w->len;                         /* hash boundary for binder */
    wn_Write_U16(w, 33);                        /* binders length */
    wn_Write_U8(w, 32);                         /* binder entry length */
    *binderOff = w->len;
    for (i = 0; i < 32; i++) {
        wn_Write_U8(w, 0);                      /* binder placeholder */
    }
    wn_Write_LenEnd(w, pskLen, 2);

    wn_Write_LenEnd(w, extLen, 2);
    wn_Write_LenEnd(w, hsLen, 3);
}

int wn_Connect_Psk(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv, void* ioCtx,
                   const byte* psk, word32 pskLen, const char* identity,
                   byte* scratch, word32 scratchLen)
{
    wn_Writer w;
    wn_Transcript tc;
    wn_KeyShare ks;
    wn_ServerHello sh;
    byte random32[32], sid[32], cliPub[32];
    byte ecdhe[32], emptyHash[32], th[32];
    byte early[32], binderKey[32], derived[32], hs[32], cHs[32], sHs[32];
    byte cKey[16], cIv[12], sKey[16], sIv[12];
    byte binder[32], mac[32], recvMac[32];
    byte fin[36];
    byte plain[512];
    word32 truncOff, binderOff, chLen, recLen, thLen, pubLen, ssLen;
    word32 plainLen, sSeq = 0;
    byte rtype, ctype;
    int ret = WOLFNANOTLS_SUCCESS;
    int gotEE = 0, done = 0;

    if ((rng == NULL) || (ioSend == NULL) || (ioRecv == NULL) || (psk == NULL) ||
        (identity == NULL) || (scratch == NULL) || (scratchLen < 2048)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wc_Sha256Hash((const byte*)"", 0, emptyHash);
        if (ret != 0) { ret = WOLFNANOTLS_E_CRYPTO; }
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wc_RNG_GenerateBlock(rng, random32, 32);
        ret |= wc_RNG_GenerateBlock(rng, sid, 32);
        if (ret != 0) { ret = WOLFNANOTLS_E_CRYPTO; }
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_KeyShare_Init(&ks, WN_GROUP_X25519);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_KeyShare_Generate(&ks, rng, cliPub, &pubLen);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_Transcript_Init(&tc, WC_SHA256);
    }

    /* ----- ClientHello with PSK binder ----- */
    if (ret == WOLFNANOTLS_SUCCESS) {
        wn_Writer_Init(&w, scratch, scratchLen);
        build_client_hello(&w, random32, sid, cliPub, identity,
                           (word32)XSTRLEN(identity), &truncOff, &binderOff);
        if (w.err != 0) { ret = WOLFNANOTLS_E_CRYPTO; }
        chLen = w.len;
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret  = wn_Tls13_Extract(early, NULL, 0, psk, pskLen, WC_SHA256);
        ret |= wn_Tls13_DeriveSecret(binderKey, early, "ext binder", emptyHash,
                                     32, WC_SHA256);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wc_Sha256Hash(scratch, truncOff, th);   /* partial CH hash */
        if (ret != 0) { ret = WOLFNANOTLS_E_CRYPTO; }
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_Tls13_FinishedMac(binder, binderKey, th, 32, WC_SHA256);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        XMEMCPY(scratch + binderOff, binder, 32);     /* backfill binder */
        ret = wn_Transcript_Update(&tc, scratch, chLen);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = send_plain_record(ioSend, ioCtx, WN_REC_HANDSHAKE, scratch, chLen);
    }

    /* ----- ServerHello ----- */
    if (ret == WOLFNANOTLS_SUCCESS) {
        do {
            ret = recv_record(ioRecv, ioCtx, scratch, scratchLen, &rtype,
                              &recLen);
        } while ((ret == WOLFNANOTLS_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER));
    }
    if ((ret == WOLFNANOTLS_SUCCESS) && (rtype != WN_REC_HANDSHAKE)) {
        ret = WOLFNANOTLS_E_CRYPTO;
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_ServerHello_Parse(scratch + 5, recLen - 5, &sh);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_Transcript_Update(&tc, scratch + 5, recLen - 5);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        if ((sh.keyShare == NULL) || (sh.keyShareLen != 32)) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_KeyShare_Shared(&ks, sh.keyShare, sh.keyShareLen, ecdhe,
                                 &ssLen);
    }

    /* ----- handshake key schedule ----- */
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret  = wn_Transcript_GetHash(&tc, th, &thLen);
        ret |= wn_Tls13_DeriveSecret(derived, early, "derived", emptyHash, 32,
                                     WC_SHA256);
        ret |= wn_Tls13_Extract(hs, derived, 32, ecdhe, 32, WC_SHA256);
        ret |= wn_Tls13_DeriveSecret(cHs, hs, "c hs traffic", th, 32,
                                     WC_SHA256);
        ret |= wn_Tls13_DeriveSecret(sHs, hs, "s hs traffic", th, 32,
                                     WC_SHA256);
        ret |= wn_Tls13_ExpandLabel(cKey, 16, cHs, "key", NULL, 0, WC_SHA256);
        ret |= wn_Tls13_ExpandLabel(cIv, 12, cHs, "iv", NULL, 0, WC_SHA256);
        ret |= wn_Tls13_ExpandLabel(sKey, 16, sHs, "key", NULL, 0, WC_SHA256);
        ret |= wn_Tls13_ExpandLabel(sIv, 12, sHs, "iv", NULL, 0, WC_SHA256);
    }

    /* ----- server encrypted flight: EncryptedExtensions + Finished ----- */
    while ((ret == WOLFNANOTLS_SUCCESS) && (done == 0)) {
        ret = recv_record(ioRecv, ioCtx, scratch, scratchLen, &rtype, &recLen);
        if ((ret == WOLFNANOTLS_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER)) {
            continue;
        }
        if ((ret == WOLFNANOTLS_SUCCESS) && (rtype != WN_REC_APPDATA)) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
        if (ret == WOLFNANOTLS_SUCCESS) {
            ret = wn_Record_Unprotect(plain, &plainLen, &ctype, sKey, 16, sIv,
                                      sSeq, scratch, recLen);
            sSeq++;
        }
        if ((ret == WOLFNANOTLS_SUCCESS) && (ctype == WN_REC_HANDSHAKE)) {
            wn_Reader hr;
            wn_Reader_Init(&hr, plain, plainLen);
            while ((hr.pos < plainLen) && (ret == WOLFNANOTLS_SUCCESS) &&
                   (done == 0)) {
                word32 mStart, mLen;
                byte mType;
                mStart = hr.pos;
                mType = wn_Read_U8(&hr);
                mLen = wn_Read_U24(&hr);
                (void)wn_Read_Bytes(&hr, mLen);
                if (hr.err != 0) {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
                else if (mType == WN_HS_ENCRYPTED_EXT) {
                    ret = wn_Transcript_Update(&tc, plain + mStart, mLen + 4);
                    gotEE = 1;
                }
                else if (mType == WN_HS_FINISHED) {
                    ret = wn_Transcript_GetHash(&tc, th, &thLen);
                    if (ret == WOLFNANOTLS_SUCCESS) {
                        ret = wn_Tls13_FinishedMac(mac, sHs, th, 32, WC_SHA256);
                    }
                    if (ret == WOLFNANOTLS_SUCCESS) {
                        XMEMCPY(recvMac, plain + mStart + 4, 32);
                        if ((mLen != 32) ||
                            (ConstantCompare(mac, recvMac, 32) != 0) ||
                            (gotEE == 0)) {
                            ret = WOLFNANOTLS_E_CRYPTO;
                        }
                    }
                    if (ret == WOLFNANOTLS_SUCCESS) {
                        ret = wn_Transcript_Update(&tc, plain + mStart, mLen + 4);
                        done = 1;
                    }
                }
                else {
                    ret = wn_Transcript_Update(&tc, plain + mStart, mLen + 4);
                }
            }
        }
    }

    /* ----- client Finished ----- */
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_Transcript_GetHash(&tc, th, &thLen);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_Tls13_FinishedMac(mac, cHs, th, 32, WC_SHA256);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        fin[0] = WN_HS_FINISHED;
        fin[1] = 0;
        fin[2] = 0;
        fin[3] = 32;
        XMEMCPY(fin + 4, mac, 32);
        ret = wn_Record_Protect(scratch, &recLen, cKey, 16, cIv, 0,
                                WN_REC_HANDSHAKE, fin, sizeof(fin));
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        if (ioSend(ioCtx, scratch, recLen) != (int)recLen) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }

    wn_KeyShare_Free(&ks);
    ForceZero(early, sizeof(early));
    ForceZero(binderKey, sizeof(binderKey));
    ForceZero(hs, sizeof(hs));
    ForceZero(cHs, sizeof(cHs));
    ForceZero(sHs, sizeof(sHs));
    ForceZero(cKey, sizeof(cKey));
    ForceZero(sKey, sizeof(sKey));

    return ret;
}
