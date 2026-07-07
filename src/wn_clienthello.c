/* wn_clienthello.c
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
 * TLS 1.3 ClientHello encoder over wn_msg. Structure per RFC 8446 4.1.2; logic
 * mirrors wolfSSL tls13.c SendTls13ClientHello. No allocation.
 */

#include "wn_clienthello.h"
#include "wn_keyshare.h"
#include "wn_msg.h"

#define WN_HS_CLIENT_HELLO   1
#define WN_EXT_SERVER_NAME   0
#define WN_SNI_MAX_HOST      255
#define WN_EXT_SUPPORTED_GRP 10
#define WN_EXT_SIG_ALGS      13
#define WN_EXT_SUPPORTED_VER 43
#define WN_EXT_KEY_SHARE     51

int wn_ClientHello_Build(byte* out, word32* outLen, word32 outCap,
                         const byte* random32, const byte* sessionId,
                         word32 sessionIdLen, const byte* pub,
                         word32 pubLen)
{
    return wn_ClientHello_Build_ex(out, outLen, outCap, random32, sessionId,
                                   sessionIdLen, pub, pubLen, NULL);
}

int wn_ClientHello_Build_ex(byte* out, word32* outLen, word32 outCap,
                            const byte* random32, const byte* sessionId,
                            word32 sessionIdLen, const byte* pub,
                            word32 pubLen, const char* serverName)
{
    wn_Writer w;
    word32 hsLen;
    word32 extLen;
    word32 saExt, saList;
    word32 nameLen = 0;
    int ret = WOLFNANO_SUCCESS;

    if (serverName != NULL) {
        nameLen = (word32)XSTRLEN(serverName);
    }
    if ((out == NULL) || (outLen == NULL) || (random32 == NULL) ||
        (pub == NULL) || (pubLen != WN_DEFAULT_PUB_SZ) || (sessionIdLen > 32) ||
        (nameLen > WN_SNI_MAX_HOST)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        wn_Writer_Init(&w, out, outCap);

        wn_Write_U8(&w, WN_HS_CLIENT_HELLO);
        hsLen = wn_Write_LenStart(&w, 3);

        wn_Write_U16(&w, 0x0303);              /* legacy_version */
        wn_Write_Bytes(&w, random32, 32);      /* random */

        wn_Write_U8(&w, (byte)sessionIdLen);   /* legacy_session_id */
        if (sessionIdLen > 0) {
            wn_Write_Bytes(&w, sessionId, sessionIdLen);
        }

        wn_Write_U16(&w, 2);                   /* cipher_suites length */
        wn_Write_U16(&w, WN_CIPHER_AES_128_GCM_SHA256);

        wn_Write_U8(&w, 1);                    /* legacy_compression_methods */
        wn_Write_U8(&w, 0);

        extLen = wn_Write_LenStart(&w, 2);     /* extensions */

        /* server_name (SNI, RFC 6066): a single host_name entry */
        if (nameLen > 0) {
            wn_Write_U16(&w, WN_EXT_SERVER_NAME);
            wn_Write_U16(&w, (word16)(2 + 1 + 2 + nameLen));
            wn_Write_U16(&w, (word16)(1 + 2 + nameLen)); /* server_name_list */
            wn_Write_U8(&w, 0);                          /* host_name */
            wn_Write_U16(&w, (word16)nameLen);
            wn_Write_Bytes(&w, (const byte*)serverName, nameLen);
        }

        /* supported_versions: [TLS 1.3] */
        wn_Write_U16(&w, WN_EXT_SUPPORTED_VER);
        wn_Write_U16(&w, 3);
        wn_Write_U8(&w, 2);
        wn_Write_U16(&w, 0x0304);

        /* supported_groups: [configured (EC)DHE group] */
        wn_Write_U16(&w, WN_EXT_SUPPORTED_GRP);
        wn_Write_U16(&w, 4);
        wn_Write_U16(&w, 2);
        wn_Write_U16(&w, WN_DEFAULT_GROUP);

        /* signature_algorithms (RFC 8446 4.2.3): the offered set is a function
         * of the compiled-in primitives; lengths self-size via LenStart/LenEnd
         * so a scheme is offered only when wn_CertVerify can check it. */
        wn_Write_U16(&w, WN_EXT_SIG_ALGS);
        saExt  = wn_Write_LenStart(&w, 2);
        saList = wn_Write_LenStart(&w, 2);
#ifdef WOLFSSL_HAVE_MLDSA
        wn_Write_U16(&w, WN_MLDSA_SCHEME);     /* ML-DSA (WOLFNANO_MLDSA_LEVEL) */
#endif
#ifdef HAVE_ED25519
        wn_Write_U16(&w, 0x0807);              /* ed25519 */
#endif
#if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
        wn_Write_U16(&w, 0x0503);              /* ecdsa_secp384r1_sha384 */
#endif
#ifdef HAVE_ECC
        wn_Write_U16(&w, 0x0403);              /* ecdsa_secp256r1_sha256 */
#endif
#ifndef NO_RSA
    #ifdef WOLFSSL_SHA512
        wn_Write_U16(&w, 0x0806);              /* rsa_pss_rsae_sha512 */
    #endif
    #ifdef WOLFSSL_SHA384
        wn_Write_U16(&w, 0x0805);              /* rsa_pss_rsae_sha384 */
    #endif
        wn_Write_U16(&w, 0x0804);              /* rsa_pss_rsae_sha256 */
#endif
        wn_Write_LenEnd(&w, saList, 2);
        wn_Write_LenEnd(&w, saExt, 2);

        /* key_share: one entry for the configured group */
        wn_Write_U16(&w, WN_EXT_KEY_SHARE);
        wn_Write_U16(&w, (word16)(2 + 2 + 2 + pubLen));
        wn_Write_U16(&w, (word16)(2 + 2 + pubLen));
        wn_Write_U16(&w, WN_DEFAULT_GROUP);
        wn_Write_U16(&w, (word16)pubLen);
        wn_Write_Bytes(&w, pub, pubLen);

        wn_Write_LenEnd(&w, extLen, 2);        /* extensions length */
        wn_Write_LenEnd(&w, hsLen, 3);         /* handshake length */

        if (w.err != 0) {
            ret = WOLFNANO_E_INVALID_ARG;
        }
        else {
            *outLen = w.len;
        }
    }

    return ret;
}

#ifdef WOLFNANO_SERVER
#define WN_EXT_PRE_SHARED_KEY 41
#define WN_EXT_SIGNATURE_ALGS 13
#define WN_EXT_SUPPORTED_GRPS 10
#define WN_EXT_SUPPORTED_VERS 43
#define WN_EXT_PSK_KEX_MODES  45

int wn_ClientHello_HasSigAlg(const wn_ClientHello* ch, word16 scheme)
{
    word16 i;
    int found = 0;

    if ((ch != NULL) && (ch->sigAlgs != NULL)) {
        for (i = 0; (i + 1) < ch->sigAlgsLen; i += 2) {
            if (((word16)(ch->sigAlgs[i] << 8) | ch->sigAlgs[i + 1]) == scheme) {
                found = 1;
            }
        }
    }

    return found;
}

int wn_ClientHello_Parse(const byte* msg, word32 msgLen, wn_ClientHello* out)
{
    wn_Reader r;
    word32 hsLen, extEnd, eEnd, ksEnd, idsEnd, ksVec;
    word16 vecLen, et, el, csLen, i, klen, idLen, idsLen, cs;
    word16 g;
    byte sidLen, compLen, comp, blen, nver, pmLen, j;
    byte seenPsk = 0, dup, nSeen = 0;
    byte haveTls13 = 0, havePskDhe = 0, haveGroups = 0, groupOffered = 0;
    word16 sv, glen;
    word16 seenExt[24];
    const byte* p;
    int ret = WOLFNANO_SUCCESS;

    if ((msg == NULL) || (out == NULL)) {
        return WOLFNANO_E_INVALID_ARG;
    }
    XMEMSET(out, 0, sizeof(*out));

    wn_Reader_Init(&r, msg, msgLen);
    if (wn_Read_U8(&r) != WN_HS_CLIENT_HELLO) {
        ret = WOLFNANO_E_UNEXPECTED_MSG;
    }
    hsLen = wn_Read_U24(&r);
    if ((ret == WOLFNANO_SUCCESS) && (r.pos + hsLen != msgLen)) {
        ret = WOLFNANO_E_DECODE;
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wn_Read_U16(&r) != 0x0303) {        /* RFC 8446 4.1.2: frozen at 1.2 */
            ret = WOLFNANO_E_DECODE;
        }
        (void)wn_Read_Bytes(&r, 32);            /* random */
        sidLen = wn_Read_U8(&r);
        if (sidLen > 32) {         /* RFC 8446 4.1.2: legacy_session_id is 0..32 */
            ret = WOLFNANO_E_DECODE;
        }
        out->sessionId = wn_Read_Bytes(&r, sidLen);
        out->sessionIdLen = sidLen;
        csLen = wn_Read_U16(&r);
        if ((ret == WOLFNANO_SUCCESS) && ((csLen & 1) != 0)) {
            ret = WOLFNANO_E_DECODE;
        }
    }
    for (i = 0; (ret == WOLFNANO_SUCCESS) && (i < csLen); i += 2) {
        cs = wn_Read_U16(&r);
        if (cs == WN_CIPHER_AES_128_GCM_SHA256) {
            out->cipher = cs;                   /* first supported suite offered */
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        compLen = wn_Read_U8(&r);
        comp = wn_Read_U8(&r);                  /* legacy_compression_methods */
        if ((compLen != 1) || (comp != 0)) {    /* RFC 8446 4.1.2: must be [null] */
            ret = WOLFNANO_E_DECODE;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        vecLen = wn_Read_U16(&r);
        extEnd = r.pos + vecLen;
        if ((r.err != 0) || (extEnd != msgLen)) {
            ret = WOLFNANO_E_DECODE;
        }
    }
    while ((ret == WOLFNANO_SUCCESS) && (r.pos < extEnd) && (r.err == 0)) {
        et = wn_Read_U16(&r);
        el = wn_Read_U16(&r);
        eEnd = r.pos + el;
        dup = 0;                                /* RFC 8446 4.2: reject any dup type */
        for (j = 0; j < nSeen; j++) {
            if (seenExt[j] == et) { dup = 1; }
        }
        if ((r.err != 0) || (eEnd > extEnd) || (seenPsk != 0) || (dup != 0) ||
            (nSeen >= (byte)(sizeof(seenExt) / sizeof(seenExt[0])))) {
            /* body overruns the block, a duplicate/too-many extensions, or an
             * extension follows pre_shared_key (RFC 8446 4.2.11: PSK is last) */
            ret = WOLFNANO_E_DECODE;
        }
        else if (et == WN_EXT_KEY_SHARE) {
            ksVec = wn_Read_U16(&r);            /* client_shares vector */
            ksEnd = r.pos + ksVec;
            if (ksEnd > eEnd) { r.err = 1; }
            while ((r.pos < ksEnd) && (r.err == 0)) {
                g = wn_Read_U16(&r);
                klen = wn_Read_U16(&r);
                p = wn_Read_Bytes(&r, klen);
                if ((g == WN_DEFAULT_GROUP) && (p != NULL)) {
                    out->keyShare = p;
                    out->keyShareLen = klen;
                    out->group = g;
                    out->haveKeyShare = 1;
                }
            }
        }
        else if (et == WN_EXT_SIGNATURE_ALGS) {
            idsLen = wn_Read_U16(&r);           /* supported_signature_algorithms */
            out->sigAlgs = wn_Read_Bytes(&r, idsLen);
            out->sigAlgsLen = idsLen;
        }
        else if (et == WN_EXT_SUPPORTED_GRPS) {
            glen = wn_Read_U16(&r);             /* named_group_list */
            haveGroups = 1;
            for (j = 0; (j + 1) < glen; j += 2) {
                if (wn_Read_U16(&r) == WN_DEFAULT_GROUP) {
                    groupOffered = 1;
                }
            }
        }
        else if (et == WN_EXT_SUPPORTED_VERS) {
            nver = wn_Read_U8(&r);              /* versions list length */
            for (j = 0; (j + 1) < nver; j += 2) {
                sv = wn_Read_U16(&r);
                if (sv == 0x0304) {             /* client offers TLS 1.3 */
                    haveTls13 = 1;
                }
            }
        }
        else if (et == WN_EXT_PSK_KEX_MODES) {
            pmLen = wn_Read_U8(&r);             /* ke_modes list length */
            for (j = 0; j < pmLen; j++) {
                if (wn_Read_U8(&r) == 1) {      /* psk_dhe_ke */
                    havePskDhe = 1;
                }
            }
        }
        else if (et == WN_EXT_PRE_SHARED_KEY) {
            seenPsk = 1;
            idsLen = wn_Read_U16(&r);           /* identities vector */
            idsEnd = r.pos + idsLen;
            idLen = wn_Read_U16(&r);
            out->pskIdentity = wn_Read_Bytes(&r, idLen);
            out->pskIdentityLen = idLen;
            if ((idsEnd >= r.pos) && (idsEnd <= eEnd)) {  /* skip further identities */
                (void)wn_Read_Bytes(&r, idsEnd - r.pos);
            }
            else {
                r.err = 1;
            }
            out->binderTruncLen = r.pos;        /* binders section starts here */
            (void)wn_Read_U16(&r);              /* binders vector length */
            blen = wn_Read_U8(&r);              /* first binder length */
            out->binder = wn_Read_Bytes(&r, blen);
            out->binderLen = blen;
            out->havePsk = 1;
            if ((r.err == 0) && (r.pos < eEnd)) {  /* consume any further binders */
                (void)wn_Read_Bytes(&r, eEnd - r.pos);
            }
        }
        else {
            (void)wn_Read_Bytes(&r, el);
        }
        /* each extension must consume exactly its declared length */
        if ((ret == WOLFNANO_SUCCESS) && ((r.err != 0) || (r.pos != eEnd))) {
            ret = WOLFNANO_E_DECODE;
        }
        if (ret == WOLFNANO_SUCCESS) {
            seenExt[nSeen++] = et;             /* record type for dup detection */
        }
    }
    /* cipher + key_share + a TLS 1.3 offer are always required (RFC 8446 4.2.1).
     * PSK binder + psk_dhe_ke only when a PSK was offered; a cert-mode ClientHello
     * carries neither, and the auth driver enforces its own mode. */
    if ((ret == WOLFNANO_SUCCESS) &&
        ((out->cipher == 0) || (out->haveKeyShare == 0) ||
         (out->keyShareLen != WN_DEFAULT_PUB_SZ) || (haveTls13 == 0) ||
         (haveGroups == 0) || (groupOffered == 0) ||
         (out->havePsk && ((out->binderLen != 32) || (havePskDhe == 0))))) {
        ret = WOLFNANO_E_ILLEGAL_PARAM;   /* RFC 8446 9.2/4.2.7: key_share group
                                           * must be in supported_groups */
    }

    return ret;
}
#endif /* WOLFNANO_SERVER */
