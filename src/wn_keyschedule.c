/* wn_keyschedule.c
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
 * TLS 1.3 key schedule over the wc_* seam. Ported from wolfSSL tls13.c
 * (DeriveKey / Tls13_HKDF_Expand_Label usage), buffers caller-provided.
 */

#include "wn_keyschedule.h"
#include "wolfnano_crypto.h"

#ifndef WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>   /* inline ForceZero, wolfSSL idiom */
#endif

static word32 wn_DigestSize(int digest)
{
    word32 sz = 0;

    if (digest == WC_SHA256) {
        sz = WC_SHA256_DIGEST_SIZE;
    }
#ifdef WOLFSSL_SHA384
    else if (digest == WC_SHA384) {
        sz = WC_SHA384_DIGEST_SIZE;
    }
#endif

    return sz;
}

int wn_Tls13_Extract(byte* prk, const byte* salt, word32 saltLen,
                     const byte* ikm, word32 ikmLen, int digest)
{
    int ret = WOLFNANO_SUCCESS;

    if ((prk == NULL) || (ikm == NULL) || (wn_DigestSize(digest) == 0)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        if (ikmLen == 0) {
            /* wolfCrypt writes a digest-sized zero block through ikm for the
             * zero-length case, so give it writable scratch, not the caller's
             * (possibly read-only) const buffer. */
            byte zikm[WC_MAX_DIGEST_SIZE];
            XMEMSET(zikm, 0, sizeof(zikm));
            ret = wc_Tls13_HKDF_Extract(prk, salt, saltLen, zikm, 0, digest);
        }
        else {
            ret = wc_Tls13_HKDF_Extract(prk, salt, saltLen, (byte*)ikm, ikmLen,
                                        digest);
        }
        /* LCOV_EXCL_START - HKDF-Extract does not fail on a validated digest */
        if (ret != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        /* LCOV_EXCL_STOP */
    }

    return ret;
}

int wn_Tls13_ExpandLabel(byte* okm, word32 okmLen, const byte* secret,
                         const char* label, const byte* info, word32 infoLen,
                         int digest)
{
    static const byte protocol[6] = { 't', 'l', 's', '1', '3', ' ' };
    int ret = WOLFNANO_SUCCESS;
    word32 hashLen;

    hashLen = wn_DigestSize(digest);
    if ((okm == NULL) || (secret == NULL) || (label == NULL) ||
        (hashLen == 0) || ((info == NULL) && (infoLen > 0))) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        ret = wc_Tls13_HKDF_Expand_Label(okm, okmLen, secret, hashLen,
                  protocol, (word32)sizeof(protocol),
                  (const byte*)label, (word32)XSTRLEN(label),
                  info, infoLen, digest);
        /* LCOV_EXCL_START - HKDF-Expand-Label does not fail on a valid digest */
        if (ret != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        /* LCOV_EXCL_STOP */
    }

    return ret;
}

int wn_Tls13_DeriveSecret(byte* out, const byte* secret, const char* label,
                          const byte* transcriptHash, word32 hashLen,
                          int digest)
{
    int ret = WOLFNANO_SUCCESS;

    if (hashLen != wn_DigestSize(digest)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_ExpandLabel(out, hashLen, secret, label,
                                   transcriptHash, hashLen, digest);
    }
    return ret;
}

int wn_Tls13_FinishedMac(byte* out, const byte* baseKey,
                         const byte* transcriptHash, word32 hashLen,
                         int digest)
{
    Hmac hmac;
    byte finishedKey[WC_MAX_DIGEST_SIZE];
    int ret = WOLFNANO_SUCCESS;
    int hmacInit = 0;

    if ((out == NULL) || (baseKey == NULL) || (transcriptHash == NULL) ||
        (hashLen == 0) || (hashLen != wn_DigestSize(digest)) ||
        (hashLen > sizeof(finishedKey))) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_ExpandLabel(finishedKey, hashLen, baseKey, "finished",
                                   NULL, 0, digest);
    }

    if (ret == WOLFNANO_SUCCESS) {
        /* LCOV_EXCL_START - wc_HmacInit does not fail without an allocator */
        if (wc_HmacInit(&hmac, NULL, INVALID_DEVID) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        /* LCOV_EXCL_STOP */
    }

    if (ret == WOLFNANO_SUCCESS) {
        hmacInit = 1;
        /* LCOV_EXCL_START - HMAC set/update/final does not fail on valid input */
        if ((wc_HmacSetKey(&hmac, digest, finishedKey, hashLen) != 0) ||
            (wc_HmacUpdate(&hmac, transcriptHash, hashLen) != 0) ||
            (wc_HmacFinal(&hmac, out) != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
        /* LCOV_EXCL_STOP */
    }

    if (hmacInit) {
        wc_HmacFree(&hmac);
    }
    ForceZero(finishedKey, sizeof(finishedKey));

    return ret;
}

int wn_Tls13_KeyUpdate(byte* secret, byte* key, byte* iv, int digest)
{
    byte newSecret[WC_MAX_DIGEST_SIZE];
    word32 hashLen;
    int ret = WOLFNANO_SUCCESS;

    hashLen = wn_DigestSize(digest);
    if ((secret == NULL) || (key == NULL) || (iv == NULL) || (hashLen == 0) ||
        (hashLen > sizeof(newSecret))) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_ExpandLabel(newSecret, hashLen, secret, "traffic upd",
                                   NULL, 0, digest);
    }
    if (ret == WOLFNANO_SUCCESS) {
        XMEMCPY(secret, newSecret, hashLen);
        ret = wn_Tls13_ExpandLabel(key, 16, secret, "key", NULL, 0, digest);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Tls13_ExpandLabel(iv, 12, secret, "iv", NULL, 0, digest);
    }

    ForceZero(newSecret, sizeof(newSecret));

    return ret;
}
