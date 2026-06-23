/* wn_hybrid.c
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
 * X25519MLKEM768 hybrid key share over the wc_* seam. ML-KEM-768 component
 * first, then X25519, per draft-kwiatkowski-tls-ecdhe-mlkem. No allocation.
 */

#include "wn_hybrid.h"

int wn_Hybrid_ClientKeyShare(wn_Hybrid* h, WC_RNG* rng, byte* out,
                             word32* outLen)
{
    word32 xLen = WN_HYBRID_X25519;
    int ret = WOLFNANO_SUCCESS;

    if ((h == NULL) || (rng == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    /* LCOV_EXCL_START - ML-KEM/curve25519 init+keygen do not fail on valid RNG */
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_MlKemKey_Init(&h->kem, WC_ML_KEM_768, NULL, INVALID_DEVID) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            h->kemInit = 1;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_MlKemKey_MakeKey(&h->kem, rng) != 0) ||
            (wc_MlKemKey_EncodePublicKey(&h->kem, out, WN_HYBRID_MLKEM_PUB)
                != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_curve25519_init(&h->x) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            h->xInit = 1;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_curve25519_make_key(rng, WN_HYBRID_X25519, &h->x) != 0) ||
            (wc_curve25519_export_public_ex(&h->x, out + WN_HYBRID_MLKEM_PUB,
                &xLen, EC25519_LITTLE_ENDIAN) != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    /* LCOV_EXCL_STOP */
    if (ret == WOLFNANO_SUCCESS) {
        *outLen = WN_HYBRID_CLIENT_SHARE;
    }

    return ret;
}

int wn_Hybrid_ClientShared(wn_Hybrid* h, const byte* srvShare, word32 srvLen,
                           byte* ss, word32* ssLen)
{
    curve25519_key peer;
    word32 xLen = WN_HYBRID_X25519;
    int ret = WOLFNANO_SUCCESS;
    int peerInit = 0;

    if ((h == NULL) || (srvShare == NULL) || (ss == NULL) || (ssLen == NULL) ||
        (srvLen != WN_HYBRID_SERVER_SHARE)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    /* LCOV_EXCL_START - ML-KEM decap (implicit reject) + curve25519 init/import/
     * shared do not fail on a well-formed server share */
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_MlKemKey_Decapsulate(&h->kem, ss, srvShare, WN_HYBRID_MLKEM_CT)
                != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_curve25519_init(&peer) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        peerInit = 1;
        if ((wc_curve25519_import_public_ex(srvShare + WN_HYBRID_MLKEM_CT,
                WN_HYBRID_X25519, &peer, EC25519_LITTLE_ENDIAN) != 0) ||
            (wc_curve25519_shared_secret_ex(&h->x, &peer,
                ss + WC_ML_KEM_SS_SZ, &xLen, EC25519_LITTLE_ENDIAN) != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    /* LCOV_EXCL_STOP */
    if (ret == WOLFNANO_SUCCESS) {
        *ssLen = WN_HYBRID_SECRET;
    }

    if (peerInit) {
        wc_curve25519_free(&peer);
    }

    return ret;
}

int wn_Hybrid_ServerRespond(const byte* cliShare, word32 cliLen, WC_RNG* rng,
                            byte* srvShare, word32* srvLen, byte* ss,
                            word32* ssLen)
{
    MlKemKey kem;
    curve25519_key srv, peer;
    word32 xLen = WN_HYBRID_X25519;
    int ret = WOLFNANO_SUCCESS;
    int kemInit = 0, srvInit = 0, peerInit = 0;

    if ((cliShare == NULL) || (rng == NULL) || (srvShare == NULL) ||
        (srvLen == NULL) || (ss == NULL) || (ssLen == NULL) ||
        (cliLen != WN_HYBRID_CLIENT_SHARE)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    if (ret == WOLFNANO_SUCCESS) {
        /* LCOV_EXCL_START - ML-KEM init does not fail without an allocator */
        if (wc_MlKemKey_Init(&kem, WC_ML_KEM_768, NULL, INVALID_DEVID) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            kemInit = 1;
        }
        /* LCOV_EXCL_STOP */
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_MlKemKey_DecodePublicKey(&kem, cliShare, WN_HYBRID_MLKEM_PUB)
                != 0) ||
            (wc_MlKemKey_Encapsulate(&kem, srvShare, ss, rng) != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    /* LCOV_EXCL_START - curve25519 init/keygen/import/shared do not fail on a
     * valid RNG and a well-formed client share */
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_curve25519_init(&srv) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            srvInit = 1;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_curve25519_make_key(rng, WN_HYBRID_X25519, &srv) != 0) ||
            (wc_curve25519_export_public_ex(&srv,
                srvShare + WN_HYBRID_MLKEM_CT, &xLen,
                EC25519_LITTLE_ENDIAN) != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if (wc_curve25519_init(&peer) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
        else {
            peerInit = 1;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_curve25519_import_public_ex(cliShare + WN_HYBRID_MLKEM_PUB,
                WN_HYBRID_X25519, &peer, EC25519_LITTLE_ENDIAN) != 0) ||
            (wc_curve25519_shared_secret_ex(&srv, &peer,
                ss + WC_ML_KEM_SS_SZ, &xLen, EC25519_LITTLE_ENDIAN) != 0)) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }
    /* LCOV_EXCL_STOP */
    if (ret == WOLFNANO_SUCCESS) {
        *srvLen = WN_HYBRID_SERVER_SHARE;
        *ssLen = WN_HYBRID_SECRET;
    }

    if (peerInit) {
        wc_curve25519_free(&peer);
    }
    if (srvInit) {
        wc_curve25519_free(&srv);
    }
    if (kemInit) {
        wc_MlKemKey_Free(&kem);
    }

    return ret;
}

int wn_Hybrid_Free(wn_Hybrid* h)
{
    int ret = WOLFNANO_SUCCESS;

    if (h == NULL) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    else {
        if (h->kemInit != 0) {
            wc_MlKemKey_Free(&h->kem);
            h->kemInit = 0;
        }
        if (h->xInit != 0) {
            wc_curve25519_free(&h->x);
            h->xInit = 0;
        }
    }

    return ret;
}
