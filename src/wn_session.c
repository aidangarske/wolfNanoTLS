/* wn_session.c
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
 * TLS 1.3 application-data session (RFC 8446 5.2 record layer, 4.6 post-
 * handshake). Sends/receives application_data over the wc_* seam, ignores
 * NewSessionTicket, and processes KeyUpdate (4.6.3). Caller buffers; no alloc.
 */

#include "wn_session.h"
#include "wn_record.h"
#include "wn_keyschedule.h"
#include "wn_msg.h"

#ifndef WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>   /* inline ForceZero, wolfSSL idiom */
#endif

#define WN_HS_NEW_SESSION_TICKET 4
#define WN_HS_KEY_UPDATE         24

#define WN_KU_NOT_REQUESTED      0
#define WN_KU_REQUESTED          1

/* Send our own KeyUpdate (update_not_requested) then rotate our write keys.
 * Uses a local record buffer so it never clobbers the session scratch that the
 * caller is still parsing. */
static int wn_session_send_key_update(wn_Session* s)
{
    byte msg[5];
    byte rec[WN_RECORD_HEADER_SZ + 5 + 1 + WN_RECORD_TAG_SZ];
    word32 recLen = 0;
    int ret;

    msg[0] = WN_HS_KEY_UPDATE;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 1;
    msg[4] = WN_KU_NOT_REQUESTED;

    ret = wn_Record_Protect(rec, &recLen, s->cKey, WN_AEAD_KEY_SZ, s->cIv,
                            s->cSeq, WN_REC_HANDSHAKE, msg, sizeof(msg));
    if (ret == WOLFNANOTLS_SUCCESS) {
        s->cSeq++;
        if (s->ioSend(s->ioCtx, rec, recLen) != (int)recLen) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_Tls13_KeyUpdate(s->cAppSecret, s->cKey, s->cIv, s->digest);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        s->cSeq = 0;
    }

    return ret;
}

/* Process a decrypted post-handshake record: skip NewSessionTicket, apply
 * KeyUpdate (rekey peer; answer + rekey self when update_requested). */
static int wn_session_posths(wn_Session* s, const byte* msg, word32 msgLen)
{
    wn_Reader r;
    word32 mLen;
    byte mType;
    byte req;
    int ret = WOLFNANOTLS_SUCCESS;

    wn_Reader_Init(&r, msg, msgLen);
    while ((r.pos < msgLen) && (ret == WOLFNANOTLS_SUCCESS)) {
        mType = wn_Read_U8(&r);
        mLen = wn_Read_U24(&r);
        if (mType == WN_HS_NEW_SESSION_TICKET) {
            (void)wn_Read_Bytes(&r, mLen);
        }
        else if (mType == WN_HS_KEY_UPDATE) {
            req = wn_Read_U8(&r);
            if ((r.err != 0) || (mLen != 1u) || (req > WN_KU_REQUESTED)) {
                ret = WOLFNANOTLS_E_DECODE;   /* RFC 8446 4.6.3: 1-byte enum {0,1} */
            }
            if (ret == WOLFNANOTLS_SUCCESS) {
                ret = wn_Tls13_KeyUpdate(s->sAppSecret, s->sKey, s->sIv,
                                         s->digest);
            }
            if (ret == WOLFNANOTLS_SUCCESS) {
                s->sSeq = 0;
                if (req == WN_KU_REQUESTED) {
                    ret = wn_session_send_key_update(s);
                }
            }
        }
        else {
            ret = WOLFNANOTLS_E_UNEXPECTED_MSG;
        }
        if ((ret == WOLFNANOTLS_SUCCESS) && (r.err != 0)) {
            ret = WOLFNANOTLS_E_DECODE;
        }
    }

    return ret;
}

int wn_Send(wn_Session* s, const byte* data, word32 len)
{
    word32 recLen = 0;
    word32 overhead = WN_RECORD_HEADER_SZ + 1 + WN_RECORD_TAG_SZ;
    int ret = WOLFNANOTLS_SUCCESS;

    if ((s == NULL) || (data == NULL)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }
    if ((ret == WOLFNANOTLS_SUCCESS) && ((s->flags & WN_SESS_CLOSED) != 0)) {
        ret = WOLFNANOTLS_E_CLOSED;
    }
    if ((ret == WOLFNANOTLS_SUCCESS) && ((s->flags & WN_SESS_ESTABLISHED) == 0)) {
        ret = WOLFNANOTLS_E_BAD_STATE;
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        if ((len > WN_MAX_PLAINTEXT) || (s->scratchLen < overhead) ||
            (len > (s->scratchLen - overhead))) {
            ret = WOLFNANOTLS_E_INVALID_ARG;   /* avoid word32 wrap on len */
        }
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = wn_Record_Protect(s->scratch, &recLen, s->cKey, WN_AEAD_KEY_SZ,
                                s->cIv, s->cSeq, WN_REC_APPDATA, data, len);
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        s->cSeq++;
        if (s->ioSend(s->ioCtx, s->scratch, recLen) != (int)recLen) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }

    return ret;
}

int wn_Recv(wn_Session* s, byte* out, word32 outCap, word32* outLen)
{
    byte* plain = NULL;
    word32 recLen;
    word32 plainLen;
    byte rtype;
    byte ctype;
    int ret = WOLFNANOTLS_SUCCESS;
    int done = 0;

    if ((s == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }
    if ((ret == WOLFNANOTLS_SUCCESS) && ((s->flags & WN_SESS_CLOSED) != 0)) {
        ret = WOLFNANOTLS_E_CLOSED;
    }
    if ((ret == WOLFNANOTLS_SUCCESS) && ((s->flags & WN_SESS_ESTABLISHED) == 0)) {
        ret = WOLFNANOTLS_E_BAD_STATE;
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        *outLen = 0;
        plain = s->scratch + WN_RECORD_HEADER_SZ;
    }

    while ((ret == WOLFNANOTLS_SUCCESS) && (done == 0)) {
        ret = wn_RecvRecord(s->ioRecv, s->ioCtx, s->scratch, s->scratchLen,
                            &rtype, &recLen);
        if ((ret == WOLFNANOTLS_SUCCESS) && (rtype == WN_REC_CHANGE_CIPHER)) {
            ret = WOLFNANOTLS_E_UNEXPECTED_MSG;   /* CCS only valid mid-handshake */
        }
        if (ret == WOLFNANOTLS_SUCCESS) {
            ret = wn_Record_Unprotect(plain, &plainLen, &ctype, s->sKey,
                      WN_AEAD_KEY_SZ, s->sIv, s->sSeq, s->scratch, recLen);
        }
        if (ret == WOLFNANOTLS_SUCCESS) {
            s->sSeq++;
            if (ctype == WN_REC_APPDATA) {
                if (plainLen > outCap) {
                    ret = WOLFNANOTLS_E_INVALID_ARG;
                }
                else {
                    XMEMCPY(out, plain, plainLen);
                    *outLen = plainLen;
                    done = 1;
                }
            }
            else if (ctype == WN_REC_HANDSHAKE) {
                ret = wn_session_posths(s, plain, plainLen);
            }
            else if (ctype == WN_REC_ALERT) {
                if ((plainLen >= 2) && (plain[1] == 0)) {
                    s->flags |= WN_SESS_CLOSED;
                    ret = WOLFNANOTLS_E_CLOSED;
                }
                else {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
            }
            else {
                ret = WOLFNANOTLS_E_UNEXPECTED_MSG;
            }
        }
    }

    return ret;
}

int wn_Close(wn_Session* s)
{
    byte body[2];
    byte rec[WN_RECORD_HEADER_SZ + 2 + 1 + WN_RECORD_TAG_SZ];
    word32 recLen = 0;
    int ret = WOLFNANOTLS_SUCCESS;

    if (s == NULL) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }

    if ((ret == WOLFNANOTLS_SUCCESS) && ((s->flags & WN_SESS_CLOSED) == 0) &&
        ((s->flags & WN_SESS_ESTABLISHED) != 0) && (s->ioSend != NULL)) {
        body[0] = 1;                            /* warning */
        body[1] = 0;                            /* close_notify */
        ret = wn_Record_Protect(rec, &recLen, s->cKey, WN_AEAD_KEY_SZ, s->cIv,
                                s->cSeq, WN_REC_ALERT, body, sizeof(body));
        if (ret == WOLFNANOTLS_SUCCESS) {
            (void)s->ioSend(s->ioCtx, rec, recLen);
        }
    }

    if (s != NULL) {
        ForceZero(s, sizeof(*s));   /* wipe even a non-established session */
    }

    return ret;
}
