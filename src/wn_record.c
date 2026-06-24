/* wn_record.c
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
 * TLS 1.3 record protection (RFC 8446 section 5.2) over the wc_* seam.
 * AES-GCM, in-place, caller-provided buffers, no allocation.
 */

#include "wn_record.h"
#include "wolfnano_crypto.h"

#ifndef WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>   /* inline ForceZero, wolfSSL idiom */
#endif

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

int wn_RecvRecord(wn_IoRecv recv, void* ctx, byte* rec, word32 cap,
                  byte* type, word32* recLen)
{
    word32 frag;
    int ret;

    ret = io_recv_exact(recv, ctx, rec, 5);
    if (ret == WOLFNANOTLS_SUCCESS) {
        *type = rec[0];
        frag = ((word32)rec[3] << 8) | rec[4];
        /* RFC 8446 5.2: TLSCiphertext.length <= 2^14 + 256 */
        if ((frag == 0) || ((frag + 5) > cap) ||
            (frag > (WN_MAX_PLAINTEXT + 256))) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }
    if (ret == WOLFNANOTLS_SUCCESS) {
        ret = io_recv_exact(recv, ctx, rec + 5, frag);
        *recLen = frag + 5;
    }
    /* RFC 8446 5: a ChangeCipherSpec is exactly one byte with the value 0x01. */
    if ((ret == WOLFNANOTLS_SUCCESS) && (*type == WN_REC_CHANGE_CIPHER) &&
        ((frag != 1) || (rec[5] != 0x01))) {
        ret = WOLFNANOTLS_E_DECODE;
    }

    return ret;
}

static void wn_BuildNonce(byte* nonce, const byte* iv, word64 seq)
{
    int i;

    XMEMCPY(nonce, iv, 12);
    for (i = 0; i < 8; i++) {        /* RFC 8446 5.3: 64-bit sequence number */
        nonce[11 - i] ^= (byte)(seq >> (8 * i));
    }
}

int wn_Record_Protect(byte* rec, word32* recLen, const byte* key, word32 keyLen,
                      const byte* iv, word64 seq, byte contentType,
                      const byte* content, word32 contentLen)
{
    Aes aes;
    byte nonce[12];
    word32 innerLen = 0;
    word32 ctLen = 0;
    int ret = WOLFNANOTLS_SUCCESS;
    int aesInit = 0;

    if ((rec == NULL) || (recLen == NULL) || (key == NULL) ||
        (iv == NULL) || (content == NULL)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }
    if ((ret == WOLFNANOTLS_SUCCESS) && (contentLen > WN_MAX_PLAINTEXT)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;   /* fits the 16-bit record length */
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        innerLen = contentLen + 1;
        ctLen = innerLen + WN_RECORD_TAG_SZ;

        wn_BuildNonce(nonce, iv, seq);

        rec[0] = 23;
        rec[1] = 0x03;
        rec[2] = 0x03;
        rec[3] = (byte)(ctLen >> 8);
        rec[4] = (byte)(ctLen & 0xff);

        XMEMCPY(rec + WN_RECORD_HEADER_SZ, content, contentLen);
        rec[WN_RECORD_HEADER_SZ + contentLen] = contentType;

        /* LCOV_EXCL_START - wc_AesInit cannot fail without an allocator */
        if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
        /* LCOV_EXCL_STOP */
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        aesInit = 1;
        if (wc_AesGcmSetKey(&aes, key, keyLen) != 0) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        *recLen = WN_RECORD_HEADER_SZ + ctLen;
        /* LCOV_EXCL_START - AES-GCM encrypt does not fail on valid inputs */
        if (wc_AesGcmEncrypt(&aes,
                rec + WN_RECORD_HEADER_SZ,
                rec + WN_RECORD_HEADER_SZ, innerLen,
                nonce, sizeof(nonce),
                rec + WN_RECORD_HEADER_SZ + innerLen, WN_RECORD_TAG_SZ,
                rec, WN_RECORD_HEADER_SZ) != 0) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
        /* LCOV_EXCL_STOP */
    }

    if (aesInit) {
        wc_AesFree(&aes);
    }
    if ((ret != WOLFNANOTLS_SUCCESS) && (rec != NULL) && (innerLen > 0)) {
        ForceZero(rec + WN_RECORD_HEADER_SZ, innerLen);   /* drop staged plaintext */
    }
    ForceZero(nonce, sizeof(nonce));

    return ret;
}

int wn_Record_Unprotect(byte* content, word32* contentLen, byte* contentType,
                        const byte* key, word32 keyLen, const byte* iv,
                        word64 seq, const byte* rec, word32 recLen)
{
    Aes aes;
    byte nonce[12];
    word32 innerLen = 0;
    word32 n;
    int ret = WOLFNANOTLS_SUCCESS;
    int aesInit = 0;

    if ((content == NULL) || (contentLen == NULL) || (contentType == NULL) ||
        (key == NULL) || (iv == NULL) || (rec == NULL)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }

    if ((ret == WOLFNANOTLS_SUCCESS) &&
        (recLen < (word32)(WN_RECORD_HEADER_SZ + WN_RECORD_TAG_SZ + 1))) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        innerLen = recLen - WN_RECORD_HEADER_SZ - WN_RECORD_TAG_SZ;
        wn_BuildNonce(nonce, iv, seq);
        /* LCOV_EXCL_START - wc_AesInit cannot fail without an allocator */
        if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
        /* LCOV_EXCL_STOP */
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        aesInit = 1;
        if (wc_AesGcmSetKey(&aes, key, keyLen) != 0) {
            ret = WOLFNANOTLS_E_CRYPTO;
        }
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        if (wc_AesGcmDecrypt(&aes, content,
                rec + WN_RECORD_HEADER_SZ, innerLen,
                nonce, sizeof(nonce),
                rec + WN_RECORD_HEADER_SZ + innerLen, WN_RECORD_TAG_SZ,
                rec, WN_RECORD_HEADER_SZ) != 0) {
            ret = WOLFNANOTLS_E_BAD_MAC;        /* AEAD tag / record auth failure */
        }
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        n = innerLen;
        while ((n > 0) && (content[n - 1] == 0)) {
            n--;
        }
        if (n == 0) {
            ret = WOLFNANOTLS_E_DECODE;         /* no content type (all padding) */
        }
        else {
            *contentType = content[n - 1];
            *contentLen = n - 1;
        }
    }

    if (aesInit) {
        wc_AesFree(&aes);
    }
    ForceZero(nonce, sizeof(nonce));

    return ret;
}
