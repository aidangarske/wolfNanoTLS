/* wn_servercert.c
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
 * TLS 1.3 server Certificate + CertificateVerify (RFC 8446 4.4.2/4.4.3).
 * The signing mirror of the client verify path; lifted from wolfSSL tls13.c
 * SendTls13Certificate / SendTls13CertificateVerify. Crypto via the wc_* seam.
 */

#include "wn_servercert.h"

#if defined(WOLFNANO_SERVER) && defined(WOLFNANO_X509)

#include "wn_msg.h"
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#if !defined(NO_RSA) && defined(WOLFNANO_RSA_FULL)
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#if defined(WOLFSSL_HAVE_MLDSA) && defined(WOLFNANO_MLDSA_SIGN)
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif

#define WN_HS_CERTIFICATE    11
#define WN_HS_CERT_VERIFY    15

int wn_ServerCert_Build(byte* out, word32* outLen, word32 outCap,
                        const byte* certDer, word32 certLen)
{
    wn_Writer w;
    word32 body, list, entry;
    int ret = WOLFNANO_SUCCESS;

    if ((out == NULL) || (outLen == NULL) || (certDer == NULL)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        wn_Writer_Init(&w, out, outCap);
        wn_Write_U8(&w, WN_HS_CERTIFICATE);
        body = wn_Write_LenStart(&w, 3);
        wn_Write_U8(&w, 0);                     /* certificate_request_context */
        list = wn_Write_LenStart(&w, 3);        /* certificate_list */
        entry = wn_Write_LenStart(&w, 3);       /* cert_data */
        wn_Write_Bytes(&w, certDer, certLen);
        wn_Write_LenEnd(&w, entry, 3);
        wn_Write_U16(&w, 0);                    /* per-cert extensions (empty) */
        wn_Write_LenEnd(&w, list, 3);
        wn_Write_LenEnd(&w, body, 3);
        if (w.err != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            *outLen = w.len;
        }
    }

    return ret;
}

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

#ifdef HAVE_ECC
static int wn_SignEcdsa(int hashType, const byte* keyDer, word32 keyLen,
                        const byte* tbs, word32 tbsLen, byte* sigOut,
                        word32* sigLen, WC_RNG* rng)
{
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* key = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL,
                                     DYNAMIC_TYPE_TMP_BUFFER);
#else
    ecc_key key[1];
#endif
    byte hash[WC_MAX_DIGEST_SIZE];
    word32 idx = 0;
    int ret = WOLFNANO_SUCCESS;
    int keyInit = 0, hashLen;

#ifdef WOLFSSL_SMALL_STACK
    if (key == NULL) {
        ret = WOLFNANO_E_CRYPTO;
    }
#endif
    hashLen = wc_HashGetDigestSize((enum wc_HashType)hashType);
    if ((ret == WOLFNANO_SUCCESS) &&
        ((hashLen <= 0) || (wc_Hash((enum wc_HashType)hashType, tbs, tbsLen,
            hash, (word32)hashLen) != 0))) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if ((ret == WOLFNANO_SUCCESS) && (wc_ecc_init(key) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    else if (ret == WOLFNANO_SUCCESS) {
        keyInit = 1;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_EccPrivateKeyDecode(keyDer, &idx, key, keyLen) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_ecc_sign_hash(hash, (word32)hashLen, sigOut, sigLen, rng, key)
            != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (keyInit) {
        wc_ecc_free(key);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
static int wn_SignEd25519(const byte* keyDer, word32 keyLen, const byte* tbs,
                          word32 tbsLen, byte* sigOut, word32* sigLen)
{
#ifdef WOLFSSL_SMALL_STACK
    ed25519_key* key = (ed25519_key*)XMALLOC(sizeof(ed25519_key), NULL,
                                             DYNAMIC_TYPE_TMP_BUFFER);
#else
    ed25519_key key[1];
#endif
    byte pub[ED25519_PUB_KEY_SIZE];
    word32 idx = 0;
    int ret = WOLFNANO_SUCCESS;
    int keyInit = 0;

#ifdef WOLFSSL_SMALL_STACK
    if (key == NULL) {
        ret = WOLFNANO_E_CRYPTO;
    }
#endif
    if ((ret == WOLFNANO_SUCCESS) && (wc_ed25519_init(key) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    else if (ret == WOLFNANO_SUCCESS) {
        keyInit = 1;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_Ed25519PrivateKeyDecode(keyDer, &idx, key, keyLen) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    /* PKCS8 Ed25519 keys carry no public key; signing mixes the encoded public
     * key A into the hash, so derive it and import it (make_public alone leaves
     * key->p unset, which would sign with A = 0 and fail verification). */
    if ((ret == WOLFNANO_SUCCESS) && (key->pubKeySet == 0)) {
        if ((wc_ed25519_make_public(key, pub, sizeof(pub)) != 0) ||
            (wc_ed25519_import_public(pub, sizeof(pub), key) != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_ed25519_sign_msg(tbs, tbsLen, sigOut, sigLen, key) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (keyInit) {
        wc_ed25519_free(key);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* HAVE_ED25519 */

#if !defined(NO_RSA) && defined(WOLFNANO_RSA_FULL)
static int wn_SignRsaPss(int hashType, int mgf, const byte* keyDer,
                         word32 keyLen, const byte* tbs, word32 tbsLen,
                         byte* sigOut, word32* sigLen, WC_RNG* rng)
{
#ifdef WOLFSSL_SMALL_STACK
    RsaKey* key = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL,
                                   DYNAMIC_TYPE_TMP_BUFFER);
#else
    RsaKey key[1];
#endif
    byte hash[WC_MAX_DIGEST_SIZE];
    word32 idx = 0;
    int ret = WOLFNANO_SUCCESS;
    int keyInit = 0, hashLen, sz;

#ifdef WOLFSSL_SMALL_STACK
    if (key == NULL) {
        ret = WOLFNANO_E_CRYPTO;
    }
#endif
    hashLen = wc_HashGetDigestSize((enum wc_HashType)hashType);
    if ((ret == WOLFNANO_SUCCESS) &&
        ((hashLen <= 0) || (wc_Hash((enum wc_HashType)hashType, tbs, tbsLen,
            hash, (word32)hashLen) != 0))) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if ((ret == WOLFNANO_SUCCESS) && (wc_InitRsaKey(key, NULL) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    else if (ret == WOLFNANO_SUCCESS) {
        keyInit = 1;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_RsaPrivateKeyDecode(keyDer, &idx, key, keyLen) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if ((ret == WOLFNANO_SUCCESS) && (wc_RsaSetRNG(key, rng) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (ret == WOLFNANO_SUCCESS) {
        sz = wc_RsaPSS_Sign(hash, (word32)hashLen, sigOut, *sigLen,
                            (enum wc_HashType)hashType, mgf, key, rng);
        if (sz < 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            *sigLen = (word32)sz;
        }
    }
    if (keyInit) {
        wc_FreeRsaKey(key);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* !NO_RSA && WOLFNANO_RSA_FULL */

#if defined(WOLFSSL_HAVE_MLDSA) && defined(WOLFNANO_MLDSA_SIGN)
#if WOLFNANO_MLDSA_LEVEL == 2
    #define WN_MLDSA_PARAM WC_ML_DSA_44
#elif WOLFNANO_MLDSA_LEVEL == 3
    #define WN_MLDSA_PARAM WC_ML_DSA_65
#else
    #define WN_MLDSA_PARAM WC_ML_DSA_87
#endif
static int wn_SignMlDsa(const byte* keyDer, word32 keyLen, const byte* tbs,
                        word32 tbsLen, byte* sigOut, word32* sigLen, WC_RNG* rng)
{
#ifdef WOLFSSL_SMALL_STACK
    wc_MlDsaKey* key = (wc_MlDsaKey*)XMALLOC(sizeof(wc_MlDsaKey), NULL,
                                             DYNAMIC_TYPE_TMP_BUFFER);
#else
    wc_MlDsaKey key[1];
#endif
    word32 idx = 0;
    int ret = WOLFNANO_SUCCESS;
    int keyInit = 0;

#ifdef WOLFSSL_SMALL_STACK
    if (key == NULL) {
        ret = WOLFNANO_E_CRYPTO;
    }
#endif
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_MlDsaKey_Init(key, NULL, INVALID_DEVID) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    else if (ret == WOLFNANO_SUCCESS) {
        keyInit = 1;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_MlDsaKey_SetParams(key, WN_MLDSA_PARAM) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_MlDsaKey_PrivateKeyDecode(key, keyDer, keyLen, &idx) != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_MlDsaKey_SignCtx(key, NULL, 0, sigOut, sigLen, tbs, tbsLen, rng)
            != 0)) {
        ret = WOLFNANO_E_CRYPTO;
    }
    if (keyInit) {
        wc_MlDsaKey_Free(key);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* WOLFSSL_HAVE_MLDSA && WOLFNANO_MLDSA_SIGN */

static int wn_SignCv(word16 scheme, const byte* keyDer, word32 keyLen,
                     const byte* tbs, word32 tbsLen, byte* sigOut,
                     word32* sigLen, WC_RNG* rng)
{
    int ret = WOLFNANO_E_UNSUPPORTED;

    switch (scheme) {
#ifdef HAVE_ECC
        case WN_SIG_ECDSA_SECP256R1_SHA256:
            ret = wn_SignEcdsa(WC_HASH_TYPE_SHA256, keyDer, keyLen, tbs, tbsLen,
                               sigOut, sigLen, rng);
            break;
    #if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
        case WN_SIG_ECDSA_SECP384R1_SHA384:
            ret = wn_SignEcdsa(WC_HASH_TYPE_SHA384, keyDer, keyLen, tbs, tbsLen,
                               sigOut, sigLen, rng);
            break;
    #endif
#endif
#ifdef HAVE_ED25519
        case WN_SIG_ED25519:
            ret = wn_SignEd25519(keyDer, keyLen, tbs, tbsLen, sigOut, sigLen);
            break;
#endif
#if !defined(NO_RSA) && defined(WOLFNANO_RSA_FULL)
        case WN_SIG_RSA_PSS_RSAE_SHA256:
            ret = wn_SignRsaPss(WC_HASH_TYPE_SHA256, WC_MGF1SHA256, keyDer,
                                keyLen, tbs, tbsLen, sigOut, sigLen, rng);
            break;
    #ifdef WOLFSSL_SHA384
        case WN_SIG_RSA_PSS_RSAE_SHA384:
            ret = wn_SignRsaPss(WC_HASH_TYPE_SHA384, WC_MGF1SHA384, keyDer,
                                keyLen, tbs, tbsLen, sigOut, sigLen, rng);
            break;
    #endif
    #ifdef WOLFSSL_SHA512
        case WN_SIG_RSA_PSS_RSAE_SHA512:
            ret = wn_SignRsaPss(WC_HASH_TYPE_SHA512, WC_MGF1SHA512, keyDer,
                                keyLen, tbs, tbsLen, sigOut, sigLen, rng);
            break;
    #endif
#endif
#if defined(WOLFSSL_HAVE_MLDSA) && defined(WOLFNANO_MLDSA_SIGN)
        case WN_MLDSA_SCHEME:
            ret = wn_SignMlDsa(keyDer, keyLen, tbs, tbsLen, sigOut, sigLen, rng);
            break;
#endif
        default:
            ret = WOLFNANO_E_UNSUPPORTED;
            break;
    }

    return ret;
}

int wn_ServerCertVerify_Sign(byte* out, word32* outLen, word32 outCap,
                             word16 scheme, const byte* keyDer, word32 keyLen,
                             const byte* th, word32 thLen, WC_RNG* rng)
{
    byte tbs[64 + 33 + 1 + WC_MAX_DIGEST_SIZE];
    wn_Writer w;
    word32 tbsLen = 0;
    word32 sigLen;
    word32 lenOff, body;
    int ret = WOLFNANO_SUCCESS;

    if ((out == NULL) || (outLen == NULL) || (keyDer == NULL) || (th == NULL) ||
        (rng == NULL) || (thLen > WC_MAX_DIGEST_SIZE)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        wn_BuildCvTbs(tbs, &tbsLen, th, thLen);
        wn_Writer_Init(&w, out, outCap);
        wn_Write_U8(&w, WN_HS_CERT_VERIFY);
        body = wn_Write_LenStart(&w, 3);
        wn_Write_U16(&w, scheme);
        lenOff = wn_Write_LenStart(&w, 2);      /* signature length */
        if (w.err != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    /* Sign directly into the output past the header; avoids a large ML-DSA copy. */
    if (ret == WOLFNANO_SUCCESS) {
        sigLen = outCap - w.len;
        ret = wn_SignCv(scheme, keyDer, keyLen, tbs, tbsLen, out + w.len,
                        &sigLen, rng);
    }
    if (ret == WOLFNANO_SUCCESS) {
        w.len += sigLen;
        wn_Write_LenEnd(&w, lenOff, 2);
        wn_Write_LenEnd(&w, body, 3);
        if (w.err != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            *outLen = w.len;
        }
    }

    return ret;
}

#endif /* WOLFNANO_SERVER && WOLFNANO_X509 */
