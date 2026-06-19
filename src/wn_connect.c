/* wn_connect.c
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
#include "wn_clienthello.h"
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

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
    int ret = WOLFNANO_SUCCESS;
    word32 got = 0;
    int r;

    while ((got < n) && (ret == WOLFNANO_SUCCESS)) {
        r = recv(ctx, buf + got, n - got);
        if (r <= 0) {
            ret = WOLFNANO_E_CRYPTO;
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
    if (ret == WOLFNANO_SUCCESS) {
        *type = rec[0];
        frag = ((word32)rec[3] << 8) | rec[4];
        if ((frag == 0) || ((frag + 5) > cap)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = io_recv_exact(recv, ctx, rec + 5, frag);
        *recLen = frag + 5;
    }

    return ret;
}

/* Send the TLS 1.3 middlebox-compatibility ChangeCipherSpec (RFC 8446 D.4). */
static int send_ccs(wn_IoSend send, void* ctx);

static int send_plain_record(wn_IoSend send, void* ctx, byte type,
                             const byte* body, word32 bodyLen)
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

static int send_ccs(wn_IoSend send, void* ctx)
{
    static const byte ccs = 0x01;

    return send_plain_record(send, ctx, WN_REC_CHANGE_CIPHER, &ccs, 1);
}

/* Build a PSK+ECDHE ClientHello body+header into w. Records the offset to hash
 * for the binder (truncOff) and where the 32-byte binder is written. */
static void build_client_hello(wn_Writer* w, const byte* random32,
                               const byte* sid, const byte* cliPub,
                               word16 group, word32 pubLen,
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
    wn_Write_U16(w, group);

    wn_Write_U16(w, 13);                        /* signature_algorithms */
    wn_Write_U16(w, 6);
    wn_Write_U16(w, 4);
    wn_Write_U16(w, 0x0807);
    wn_Write_U16(w, 0x0403);

    wn_Write_U16(w, 51);                        /* key_share */
    wn_Write_U16(w, (word16)(6 + pubLen));
    wn_Write_U16(w, (word16)(4 + pubLen));
    wn_Write_U16(w, group);
    wn_Write_U16(w, (word16)pubLen);
    wn_Write_Bytes(w, cliPub, pubLen);

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

#ifdef WOLFNANO_SEND_ALERTS
/* Map an internal error to a TLS 1.3 alert description (RFC 8446 6.2). */
static byte wn_ErrToAlert(int ret)
{
    byte d;
    switch (ret) {
        case WOLFNANO_E_UNEXPECTED_MSG: d = 10; break;  /* unexpected_message */
        case WOLFNANO_E_BAD_MAC:        d = 20; break;  /* bad_record_mac */
        case WOLFNANO_E_DECODE:         d = 50; break;  /* decode_error */
        case WOLFNANO_E_ILLEGAL_PARAM:  d = 47; break;  /* illegal_parameter */
        case WOLFNANO_E_BAD_CERT:       d = 42; break;  /* bad_certificate */
        default:                        d = 80; break;  /* internal_error */
    }
    return d;
}

/* Send a fatal, encrypted alert with the client handshake key (best effort). */
static void wn_SendAlert(wn_IoSend ioSend, void* ioCtx, const byte* key,
                         const byte* iv, int ret)
{
    byte body[2];
    byte rec[WN_RECORD_HEADER_SZ + 2 + 1 + WN_RECORD_TAG_SZ];
    word32 recLen = 0;

    body[0] = 2;                                /* fatal */
    body[1] = wn_ErrToAlert(ret);
    if (wn_Record_Protect(rec, &recLen, key, 16, iv, 0, WN_REC_ALERT,
                          body, sizeof(body)) == WOLFNANO_SUCCESS) {
        (void)ioSend(ioCtx, rec, recLen);
    }
}
#endif /* WOLFNANO_SEND_ALERTS */

int wn_Connect_Psk(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv, void* ioCtx,
                   const byte* psk, word32 pskLen, const char* identity,
                   byte* scratch, word32 scratchLen)
{
    wn_Writer w;
    wn_Transcript tc;
    wn_KeyShare ks;
    wn_ServerHello sh;
    byte random32[32], sid[32], cliPub[WN_KEYSHARE_MAX_PUB];
    byte ecdhe[32], emptyHash[32], th[32];
    byte early[32], binderKey[32], derived[32], hs[32], cHs[32], sHs[32];
    byte cKey[16], cIv[12], sKey[16], sIv[12];
    byte binder[32], mac[32], recvMac[32];
    byte fin[36];
    byte plain[512];
    word32 truncOff, binderOff, chLen, recLen, thLen, pubLen, ssLen;
    word32 plainLen, sSeq = 0;
    byte rtype = 0, ctype = 0;
    int ret = WOLFNANO_SUCCESS;
    int gotEE = 0, done = 0;

    if ((rng == NULL) || (ioSend == NULL) || (ioRecv == NULL) || (psk == NULL) ||
        (identity == NULL) || (scratch == NULL) || (scratchLen < 2048)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        ret = wc_Sha256Hash((const byte*)"", 0, emptyHash);
        if (ret != 0) { ret = WOLFNANO_E_CRYPTO; }
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wc_RNG_GenerateBlock(rng, random32, 32);
        ret |= wc_RNG_GenerateBlock(rng, sid, 32);
        if (ret != 0) { ret = WOLFNANO_E_CRYPTO; }
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_KeyShare_Init(&ks, WN_DEFAULT_GROUP);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_KeyShare_Generate(&ks, rng, cliPub, &pubLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Init(&tc, WC_SHA256);
    }

    /* ----- ClientHello with PSK binder ----- */
    if (ret == WOLFNANO_SUCCESS) {
        wn_Writer_Init(&w, scratch, scratchLen);
        build_client_hello(&w, random32, sid, cliPub, WN_DEFAULT_GROUP, pubLen,
                           identity, (word32)XSTRLEN(identity),
                           &truncOff, &binderOff);
        if (w.err != 0) { ret = WOLFNANO_E_CRYPTO; }
        chLen = w.len;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret  = wn_Tls13_Extract(early, NULL, 0, psk, pskLen, WC_SHA256);
        ret |= wn_Tls13_DeriveSecret(binderKey, early, "ext binder", emptyHash,
                                     32, WC_SHA256);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wc_Sha256Hash(scratch, truncOff, th);   /* partial CH hash */
        if (ret != 0) { ret = WOLFNANO_E_CRYPTO; }
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_FinishedMac(binder, binderKey, th, 32, WC_SHA256);
    }
    if (ret == WOLFNANO_SUCCESS) {
        XMEMCPY(scratch + binderOff, binder, 32);     /* backfill binder */
        ret = wn_Transcript_Update(&tc, scratch, chLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = send_plain_record(ioSend, ioCtx, WN_REC_HANDSHAKE, scratch, chLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = send_ccs(ioSend, ioCtx);     /* compat CCS after ClientHello */
    }

    /* ----- ServerHello ----- */
    if (ret == WOLFNANO_SUCCESS) {
        do {
            ret = recv_record(ioRecv, ioCtx, scratch, scratchLen, &rtype,
                              &recLen);
        } while ((ret == WOLFNANO_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER));
    }
    if ((ret == WOLFNANO_SUCCESS) && (rtype != WN_REC_HANDSHAKE)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ServerHello_Parse(scratch + 5, recLen - 5, &sh);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, scratch + 5, recLen - 5);
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((sh.keyShare == NULL) || (sh.keyShareLen != WN_DEFAULT_PUB_SZ)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_KeyShare_Shared(&ks, sh.keyShare, sh.keyShareLen, ecdhe,
                                 &ssLen);
    }

    /* ----- handshake key schedule ----- */
    if (ret == WOLFNANO_SUCCESS) {
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
    while ((ret == WOLFNANO_SUCCESS) && (done == 0)) {
        ret = recv_record(ioRecv, ioCtx, scratch, scratchLen, &rtype, &recLen);
        if ((ret == WOLFNANO_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER)) {
            continue;
        }
        if ((ret == WOLFNANO_SUCCESS) && (rtype != WN_REC_APPDATA)) {
            ret = WOLFNANO_E_CRYPTO;
        }
        if (ret == WOLFNANO_SUCCESS) {
            ret = wn_Record_Unprotect(plain, &plainLen, &ctype, sKey, 16, sIv,
                                      sSeq, scratch, recLen);
            sSeq++;
        }
        if ((ret == WOLFNANO_SUCCESS) && (ctype == WN_REC_HANDSHAKE)) {
            wn_Reader hr;
            wn_Reader_Init(&hr, plain, plainLen);
            while ((hr.pos < plainLen) && (ret == WOLFNANO_SUCCESS) &&
                   (done == 0)) {
                word32 mStart, mLen;
                byte mType;
                mStart = hr.pos;
                mType = wn_Read_U8(&hr);
                mLen = wn_Read_U24(&hr);
                (void)wn_Read_Bytes(&hr, mLen);
                if (hr.err != 0) {
                    ret = WOLFNANO_E_CRYPTO;
                }
                else if (mType == WN_HS_ENCRYPTED_EXT) {
                    ret = wn_Transcript_Update(&tc, plain + mStart, mLen + 4);
                    gotEE = 1;
                }
                else if (mType == WN_HS_FINISHED) {
                    ret = wn_Transcript_GetHash(&tc, th, &thLen);
                    if (ret == WOLFNANO_SUCCESS) {
                        ret = wn_Tls13_FinishedMac(mac, sHs, th, 32, WC_SHA256);
                    }
                    if (ret == WOLFNANO_SUCCESS) {
                        XMEMCPY(recvMac, plain + mStart + 4, 32);
                        if ((mLen != 32) ||
                            (ConstantCompare(mac, recvMac, 32) != 0) ||
                            (gotEE == 0)) {
                            ret = WOLFNANO_E_CRYPTO;
                        }
                    }
                    if (ret == WOLFNANO_SUCCESS) {
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
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_GetHash(&tc, th, &thLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_FinishedMac(mac, cHs, th, 32, WC_SHA256);
    }
    if (ret == WOLFNANO_SUCCESS) {
        fin[0] = WN_HS_FINISHED;
        fin[1] = 0;
        fin[2] = 0;
        fin[3] = 32;
        XMEMCPY(fin + 4, mac, 32);
        ret = wn_Record_Protect(scratch, &recLen, cKey, 16, cIv, 0,
                                WN_REC_HANDSHAKE, fin, sizeof(fin));
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (ioSend(ioCtx, scratch, recLen) != (int)recLen) {
            ret = WOLFNANO_E_CRYPTO;
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

#ifdef WOLFNANO_X509

#define WN_HS_CERTIFICATE 11
#define WN_HS_CERT_VERIFY 15
#define WN_HS_CERT_REQUEST 13
#define WN_MAX_CHAIN      4

/* Build the TLS 1.3 CertificateVerify signed content (RFC 8446 4.4.3). */
static void wn_BuildCvTbs(byte* tbs, word32* tbsLen, const byte* th,
                          word32 thLen)
{
    static const char label[] = "TLS 1.3, server CertificateVerify";

    XMEMSET(tbs, 0x20, 64);
    XMEMCPY(tbs + 64, label, 33);
    tbs[97] = 0x00;
    XMEMCPY(tbs + 98, th, thLen);
    *tbsLen = 98 + thLen;
}

static int wn_CvEcdsa(const byte* spki, word32 spkiLen, int hashType,
                      const byte* tbs, word32 tbsLen, const byte* sig,
                      word32 sigLen)
{
    ecc_key key;
    byte hash[WC_MAX_DIGEST_SIZE];
    word32 idx = 0;
    int ret = WOLFNANO_SUCCESS;
    int res = 0, keyInit = 0, hashLen;

    hashLen = wc_HashGetDigestSize((enum wc_HashType)hashType);
    if ((hashLen <= 0) || (wc_Hash((enum wc_HashType)hashType, tbs, tbsLen,
            hash, (word32)hashLen) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_ecc_init(&key) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            keyInit = 1;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_EccPublicKeyDecode(spki, &idx, &key, spkiLen) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_ecc_verify_hash(sig, sigLen, hash, (word32)hashLen, &res,
                &key) != 0) || (res != 1)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (keyInit) {
        wc_ecc_free(&key);
    }

    return ret;
}

#ifdef HAVE_ED25519
static int wn_CvEd25519(const byte* spki, word32 spkiLen, const byte* tbs,
                        word32 tbsLen, const byte* sig, word32 sigLen)
{
    ed25519_key key;
    word32 idx = 0;
    int ret = WOLFNANO_SUCCESS;
    int res = 0, keyInit = 0;

    if (wc_ed25519_init(&key) != 0) {
        ret = WOLFNANO_E_CRYPTO;
    }
    else {
        keyInit = 1;
    }
    if (ret == WOLFNANO_SUCCESS) {
        /* DecodedCert yields the raw 32-byte Ed25519 key, not an SPKI. */
        if (spkiLen == ED25519_PUB_KEY_SIZE) {
            if (wc_ed25519_import_public(spki, spkiLen, &key) != 0) {
                ret = WOLFNANO_E_CRYPTO;
            }
        }
        else if (wc_Ed25519PublicKeyDecode(spki, &idx, &key, spkiLen) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_ed25519_verify_msg(sig, sigLen, tbs, tbsLen, &res, &key) != 0)
                || (res != 1)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (keyInit) {
        wc_ed25519_free(&key);
    }

    return ret;
}
#endif /* HAVE_ED25519 */

#ifndef NO_RSA
static int wn_CvRsaPss(const byte* spki, word32 spkiLen, int hashType, int mgf,
                       const byte* tbs, word32 tbsLen, const byte* sig,
                       word32 sigLen)
{
    RsaKey key;
    byte hash[WC_MAX_DIGEST_SIZE];
    byte out[512];
    word32 idx = 0;
    int ret = WOLFNANO_SUCCESS;
    int keyInit = 0, hashLen;

    hashLen = wc_HashGetDigestSize((enum wc_HashType)hashType);
    if ((hashLen <= 0) || (wc_Hash((enum wc_HashType)hashType, tbs, tbsLen,
            hash, (word32)hashLen) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_InitRsaKey(&key, NULL) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            keyInit = 1;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_RsaPublicKeyDecode(spki, &idx, &key, spkiLen) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_RsaPSS_VerifyCheck((byte*)sig, sigLen, out, (word32)sizeof(out),
                hash, (word32)hashLen, (enum wc_HashType)hashType, mgf, &key)
                < 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (keyInit) {
        wc_FreeRsaKey(&key);
    }

    return ret;
}
#endif /* !NO_RSA */

/* Verify a TLS 1.3 server CertificateVerify over the transcript hash. */
static int wn_CertVerify(word16 scheme, const byte* spki, word32 spkiLen,
                         const byte* th, word32 thLen, const byte* sig,
                         word32 sigLen)
{
    byte tbs[64 + 33 + 1 + WC_MAX_DIGEST_SIZE];
    word32 tbsLen = 0;
    int ret = WOLFNANO_SUCCESS;

    wn_BuildCvTbs(tbs, &tbsLen, th, thLen);

    if (scheme == 0x0403) {
        ret = wn_CvEcdsa(spki, spkiLen, WC_HASH_TYPE_SHA256, tbs, tbsLen, sig,
                         sigLen);
    }
#ifdef WOLFSSL_SHA384
    else if (scheme == 0x0503) {
        ret = wn_CvEcdsa(spki, spkiLen, WC_HASH_TYPE_SHA384, tbs, tbsLen, sig,
                         sigLen);
    }
#endif
#ifdef HAVE_ED25519
    else if (scheme == 0x0807) {
        ret = wn_CvEd25519(spki, spkiLen, tbs, tbsLen, sig, sigLen);
    }
#endif
#ifndef NO_RSA
    else if (scheme == 0x0804) {
        ret = wn_CvRsaPss(spki, spkiLen, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                          tbs, tbsLen, sig, sigLen);
    }
#ifdef WOLFSSL_SHA384
    else if (scheme == 0x0805) {
        ret = wn_CvRsaPss(spki, spkiLen, WC_HASH_TYPE_SHA384, WC_MGF1SHA384,
                          tbs, tbsLen, sig, sigLen);
    }
#endif
#endif
    else {
        ret = WOLFNANO_E_UNSUPPORTED;
    }

    return ret;
}

/* Verify a presented cert chain (leaf first) up to the pinned anchor: each
 * cert must be signed by the next, and the topmost by the anchor. Copies the
 * leaf SPKI out for CertificateVerify. Signature-chain only (no constraint or
 * name checks yet). */
static int wn_VerifyChain(const byte** certs, const word32* certLens, int n,
                          const byte* anchor, word32 anchorLen, byte* spki,
                          word32* spkiLen)
{
    DecodedCert issuer;
    DecodedCert leaf;
    const byte* issuerDer;
    word32 issuerLen;
    int i;
    int ret = WOLFNANO_SUCCESS;
    int leafInit = 0;

    if (n < 1) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    for (i = 0; (i < n) && (ret == WOLFNANO_SUCCESS); i++) {
        if ((i + 1) < n) {
            issuerDer = certs[i + 1];
            issuerLen = certLens[i + 1];
        }
        else {
            issuerDer = anchor;
            issuerLen = anchorLen;
        }
        wc_InitDecodedCert(&issuer, issuerDer, issuerLen, NULL);
        if (wc_ParseCert(&issuer, CERT_TYPE, NO_VERIFY, NULL) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            if (CheckCertSignaturePubKey(certs[i], certLens[i], NULL,
                    issuer.publicKey, issuer.pubKeySize, issuer.keyOID) != 0) {
                ret = WOLFNANO_E_CRYPTO;
            }
            wc_FreeDecodedCert(&issuer);
        }
    }

    if (ret == WOLFNANO_SUCCESS) {
        wc_InitDecodedCert(&leaf, certs[0], certLens[0], NULL);
        if (wc_ParseCert(&leaf, CERT_TYPE, NO_VERIFY, NULL) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            leafInit = 1;
            if (leaf.pubKeySize > *spkiLen) {
                ret = WOLFNANO_E_CRYPTO;
            }
            else {
                XMEMCPY(spki, leaf.publicKey, leaf.pubKeySize);
                *spkiLen = leaf.pubKeySize;
            }
        }
    }
    if (leafInit) {
        wc_FreeDecodedCert(&leaf);
    }

    return ret;
}

int wn_Connect_Cert(WC_RNG* rng, wn_IoSend ioSend, wn_IoRecv ioRecv,
                    void* ioCtx, const byte* anchor, word32 anchorLen,
                    byte* scratch, word32 scratchLen)
{
    wn_Transcript tc;
    wn_KeyShare ks;
    wn_ServerHello sh;
    wn_Reader hr;
    byte random32[32], sid[32], cliPub[WN_KEYSHARE_MAX_PUB];
    byte ecdhe[32], emptyHash[32], th[32], thCert[32];
    byte zeros[32];
    byte early[32], derived[32], hs[32], cHs[32], sHs[32];
    byte cKey[16], cIv[12], sKey[16], sIv[12];
    byte mac[32];
    byte fin[36];
    byte hsacc[6144];
    byte leafSpki[1024];
    byte plain[2048];
    const byte* certs[WN_MAX_CHAIN];
    word32 certLens[WN_MAX_CHAIN];
    word32 chLen, recLen, thLen, pubLen, ssLen, plainLen, spkiLen = 0;
    word32 accLen = 0, sSeq = 0, off = 0;
    byte rtype = 0, ctype = 0;
    int ret = WOLFNANO_SUCCESS;
    int done = 0, gotEE = 0, gotCert = 0, gotCv = 0;
#ifdef WOLFNANO_SEND_ALERTS
    int keysReady = 0;
#endif

    if ((rng == NULL) || (ioSend == NULL) || (ioRecv == NULL) ||
        (anchor == NULL) || (scratch == NULL) || (scratchLen < 4096)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        XMEMSET(zeros, 0, sizeof(zeros));
        if ((wc_Sha256Hash((const byte*)"", 0, emptyHash) != 0) ||
            (wc_RNG_GenerateBlock(rng, random32, 32) != 0) ||
            (wc_RNG_GenerateBlock(rng, sid, 32) != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_KeyShare_Init(&ks, WN_DEFAULT_GROUP);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_KeyShare_Generate(&ks, rng, cliPub, &pubLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Init(&tc, WC_SHA256);
    }

    /* ClientHello (ECDHE, no PSK) */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ClientHello_Build(scratch, &chLen, scratchLen, random32, sid,
                                   32, cliPub, pubLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, scratch, chLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = send_plain_record(ioSend, ioCtx, WN_REC_HANDSHAKE, scratch,
                                chLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = send_ccs(ioSend, ioCtx);     /* compat CCS after ClientHello */
    }

    /* ServerHello */
    if (ret == WOLFNANO_SUCCESS) {
        do {
            ret = recv_record(ioRecv, ioCtx, scratch, scratchLen, &rtype,
                              &recLen);
        } while ((ret == WOLFNANO_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER));
    }
    if ((ret == WOLFNANO_SUCCESS) && (rtype != WN_REC_HANDSHAKE)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_ServerHello_Parse(scratch + 5, recLen - 5, &sh);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_Update(&tc, scratch + 5, recLen - 5);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        ((sh.keyShare == NULL) || (sh.keyShareLen != WN_DEFAULT_PUB_SZ))) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_KeyShare_Shared(&ks, sh.keyShare, sh.keyShareLen, ecdhe,
                                 &ssLen);
    }

    /* handshake key schedule (PSK = 0) */
    if (ret == WOLFNANO_SUCCESS) {
        ret  = wn_Transcript_GetHash(&tc, th, &thLen);
        ret |= wn_Tls13_Extract(early, NULL, 0, zeros, sizeof(zeros),
                                WC_SHA256);
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
#ifdef WOLFNANO_SEND_ALERTS
        if (ret == WOLFNANO_SUCCESS) { keysReady = 1; }
#endif
    }

    /* server flight: EncryptedExtensions, Certificate, CertVerify, Finished */
    while ((ret == WOLFNANO_SUCCESS) && (done == 0)) {
        ret = recv_record(ioRecv, ioCtx, scratch, scratchLen, &rtype, &recLen);
        if ((ret == WOLFNANO_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER)) {
            continue;
        }
        if ((ret == WOLFNANO_SUCCESS) && (rtype != WN_REC_APPDATA)) {
            ret = WOLFNANO_E_CRYPTO;
        }
        if (ret == WOLFNANO_SUCCESS) {
            ret = wn_Record_Unprotect(plain, &plainLen, &ctype, sKey, 16, sIv,
                                      sSeq, scratch, recLen);
            sSeq++;
        }
        if ((ret == WOLFNANO_SUCCESS) && (ctype == WN_REC_HANDSHAKE)) {
            if ((accLen + plainLen) > sizeof(hsacc)) {
                ret = WOLFNANO_E_CRYPTO;
            }
            else {
                XMEMCPY(hsacc + accLen, plain, plainLen);
                accLen += plainLen;
            }
        }

        /* parse complete handshake messages out of the accumulator */
        while ((ret == WOLFNANO_SUCCESS) && (done == 0) &&
               ((accLen - off) >= 4)) {
            byte mType = hsacc[off];
            word32 mLen = ((word32)hsacc[off + 1] << 16) |
                          ((word32)hsacc[off + 2] << 8) | hsacc[off + 3];
            if ((off + 4 + mLen) > accLen) {
                break;                          /* message not complete yet */
            }
            /* enforce the legal flight order EE [CertReq] Cert CertVerify
             * Finished; reject out-of-order / unexpected types (RFC 8446 4.4). */
            if (mType == WN_HS_ENCRYPTED_EXT) {
                if (gotEE) { ret = WOLFNANO_E_UNEXPECTED_MSG; }
                gotEE = 1;
            }
            else if (mType == WN_HS_CERT_REQUEST) {
                if ((gotEE == 0) || gotCert) { ret = WOLFNANO_E_UNEXPECTED_MSG; }
            }
            else if (mType == WN_HS_CERTIFICATE) {
                if ((gotEE == 0) || gotCert) { ret = WOLFNANO_E_UNEXPECTED_MSG; }
            }
            else if (mType == WN_HS_CERT_VERIFY) {
                if ((gotCert == 0) || gotCv) { ret = WOLFNANO_E_UNEXPECTED_MSG; }
            }
            else if (mType == WN_HS_FINISHED) {
                if (gotCv == 0) { ret = WOLFNANO_E_UNEXPECTED_MSG; }
            }
            else {
                ret = WOLFNANO_E_UNEXPECTED_MSG;
            }
            if ((ret == WOLFNANO_SUCCESS) && (mType == WN_HS_CERT_VERIFY)) {
                ret = wn_Transcript_GetHash(&tc, thCert, &thLen);
            }
            if ((ret == WOLFNANO_SUCCESS) && (mType == WN_HS_FINISHED)) {
                ret = wn_Transcript_GetHash(&tc, th, &thLen);
            }
            if (ret == WOLFNANO_SUCCESS) {
                ret = wn_Transcript_Update(&tc, hsacc + off, mLen + 4);
            }
            if ((ret == WOLFNANO_SUCCESS) && (mType == WN_HS_CERTIFICATE)) {
                int nc = 0;
                word32 cl;
                word16 extl;
                wn_Reader_Init(&hr, hsacc + off + 4, mLen);
                (void)wn_Read_Bytes(&hr, wn_Read_U8(&hr)); /* cert_req_context */
                (void)wn_Read_U24(&hr);                    /* cert_list length */
                while ((hr.pos < mLen) && (nc < WN_MAX_CHAIN) &&
                       (hr.err == 0)) {
                    cl = wn_Read_U24(&hr);                  /* cert_data length */
                    certs[nc] = hsacc + off + 4 + hr.pos;
                    certLens[nc] = cl;
                    nc++;
                    (void)wn_Read_Bytes(&hr, cl);
                    extl = wn_Read_U16(&hr);               /* entry extensions */
                    (void)wn_Read_Bytes(&hr, extl);
                }
                spkiLen = (word32)sizeof(leafSpki);
                if (hr.err != 0) {
                    ret = WOLFNANO_E_DECODE;
                }
                else {
                    ret = wn_VerifyChain(certs, certLens, nc, anchor, anchorLen,
                                         leafSpki, &spkiLen);
                }
                gotCert = 1;
            }
            if ((ret == WOLFNANO_SUCCESS) && (mType == WN_HS_CERT_VERIFY)) {
                word16 scheme;
                word16 cvLen;
                wn_Reader_Init(&hr, hsacc + off + 4, mLen);
                scheme = wn_Read_U16(&hr);
                cvLen = wn_Read_U16(&hr);
                if ((hr.err != 0) || (gotCert == 0)) {
                    ret = WOLFNANO_E_CRYPTO;
                }
                else {
                    ret = wn_CertVerify(scheme, leafSpki, spkiLen, thCert, 32,
                              hsacc + off + 4 + hr.pos, cvLen);
                }
                gotCv = 1;
            }
            if ((ret == WOLFNANO_SUCCESS) && (mType == WN_HS_FINISHED)) {
                if (gotCv == 0) {
                    ret = WOLFNANO_E_CRYPTO;
                }
                if (ret == WOLFNANO_SUCCESS) {
                    ret = wn_Tls13_FinishedMac(mac, sHs, th, 32, WC_SHA256);
                }
                if ((ret == WOLFNANO_SUCCESS) &&
                    ((mLen != 32) ||
                     (ConstantCompare(mac, hsacc + off + 4, 32) != 0))) {
                    ret = WOLFNANO_E_BAD_MAC;
                }
                if (ret == WOLFNANO_SUCCESS) {
                    done = 1;
                }
            }
            off += 4 + mLen;
        }
    }

    /* client Finished */
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Transcript_GetHash(&tc, th, &thLen);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_FinishedMac(mac, cHs, th, 32, WC_SHA256);
    }
    if (ret == WOLFNANO_SUCCESS) {
        fin[0] = WN_HS_FINISHED;
        fin[1] = 0;
        fin[2] = 0;
        fin[3] = 32;
        XMEMCPY(fin + 4, mac, 32);
        ret = wn_Record_Protect(scratch, &recLen, cKey, 16, cIv, 0,
                                WN_REC_HANDSHAKE, fin, sizeof(fin));
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (ioSend(ioCtx, scratch, recLen) != (int)recLen) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

#ifdef WOLFNANO_SEND_ALERTS
    if ((ret < 0) && keysReady) {
        wn_SendAlert(ioSend, ioCtx, cKey, cIv, ret);
    }
#endif

    wn_KeyShare_Free(&ks);
    ForceZero(early, sizeof(early));
    ForceZero(hs, sizeof(hs));
    ForceZero(cHs, sizeof(cHs));
    ForceZero(sHs, sizeof(sHs));
    ForceZero(cKey, sizeof(cKey));
    ForceZero(sKey, sizeof(sKey));

    return ret;
}

#endif /* WOLFNANO_X509 */
