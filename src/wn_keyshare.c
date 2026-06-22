/* wn_keyshare.c
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
 * TLS 1.3 X25519 key share over the wc_* seam. Wire format is little-endian
 * (RFC 7748). Ported from wolfSSL curve25519 usage; caller-held context.
 */

#include "wn_keyshare.h"

int wn_KeyShare_Init(wn_KeyShare* ks, int group)
{
    int ret = WOLFNANOTLS_SUCCESS;

    if (ks == NULL) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        ks->group = group;
#ifndef WOLFNANOTLS_HAVE_ECDHE_P256
        if (group == WN_GROUP_X25519) {
            /* LCOV_EXCL_START - curve25519 init does not fail without alloc */
            if (wc_curve25519_init(&ks->x25519) != 0) {
                ret = WOLFNANOTLS_E_CRYPTO;
            }
            /* LCOV_EXCL_STOP */
        }
        else
#else
        if (group == WN_GROUP_SECP256R1) {
            if (wc_ecc_init(&ks->ecc) != 0) {
                ret = WOLFNANOTLS_E_CRYPTO;
            }
        }
        else
#endif
        {
            ret = WOLFNANOTLS_E_UNSUPPORTED;
        }
    }

    return ret;
}

int wn_KeyShare_Generate(wn_KeyShare* ks, WC_RNG* rng, byte* pub,
                         word32* pubLen)
{
    int ret = WOLFNANOTLS_SUCCESS;

    if ((ks == NULL) || (rng == NULL) || (pub == NULL) || (pubLen == NULL)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
#ifndef WOLFNANOTLS_HAVE_ECDHE_P256
        if (ks->group == WN_GROUP_X25519) {
            /* LCOV_EXCL_START - keygen/export do not fail with a valid RNG */
            if (wc_curve25519_make_key(rng, WN_X25519_KEY_SZ, &ks->x25519) != 0) {
                ret = WOLFNANOTLS_E_CRYPTO;
            }
            if (ret == WOLFNANOTLS_SUCCESS) {
                *pubLen = WN_X25519_KEY_SZ;
                if (wc_curve25519_export_public_ex(&ks->x25519, pub, pubLen,
                                               EC25519_LITTLE_ENDIAN) != 0) {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
            }
            /* LCOV_EXCL_STOP */
        }
        else
#else
        if (ks->group == WN_GROUP_SECP256R1) {
            if (wc_ecc_make_key_ex(rng, 32, &ks->ecc, ECC_SECP256R1) != 0) {
                ret = WOLFNANOTLS_E_CRYPTO;
            }
            if (ret == WOLFNANOTLS_SUCCESS) {
                if (wc_ecc_set_rng(&ks->ecc, rng) != 0) {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
            }
            if (ret == WOLFNANOTLS_SUCCESS) {
                *pubLen = WN_SECP256R1_PUB_SZ;
                if (wc_ecc_export_x963(&ks->ecc, pub, pubLen) != 0) {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
            }
        }
        else
#endif
        {
            ret = WOLFNANOTLS_E_UNSUPPORTED;
        }
    }

    return ret;
}

int wn_KeyShare_Shared(wn_KeyShare* ks, const byte* peerPub, word32 peerPubLen,
                       byte* out, word32* outLen)
{
#ifdef WOLFNANOTLS_HAVE_ECDHE_P256
    ecc_key eccPeer;
#else
    curve25519_key peer;
#endif
    int ret = WOLFNANOTLS_SUCCESS;
    int peerInit = 0;

    if ((ks == NULL) || (peerPub == NULL) || (out == NULL) ||
        (outLen == NULL)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
#ifndef WOLFNANOTLS_HAVE_ECDHE_P256
        if (ks->group == WN_GROUP_X25519) {
            if (peerPubLen != WN_X25519_KEY_SZ) {
                ret = WOLFNANOTLS_E_INVALID_ARG;
            }
            /* LCOV_EXCL_START - peer init/import do not fail on a 32-byte key */
            if ((ret == WOLFNANOTLS_SUCCESS) && (wc_curve25519_init(&peer) != 0)) {
                ret = WOLFNANOTLS_E_CRYPTO;
            }
            /* LCOV_EXCL_STOP */
            if (ret == WOLFNANOTLS_SUCCESS) {
                peerInit = 1;
                /* LCOV_EXCL_START - import accepts any 32-byte public key */
                if (wc_curve25519_import_public_ex(peerPub, peerPubLen, &peer,
                                               EC25519_LITTLE_ENDIAN) != 0) {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
                /* LCOV_EXCL_STOP */
            }
            if (ret == WOLFNANOTLS_SUCCESS) {
                *outLen = WN_X25519_KEY_SZ;
                if (wc_curve25519_shared_secret_ex(&ks->x25519, &peer, out,
                                               outLen, EC25519_LITTLE_ENDIAN)
                                               != 0) {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
            }
            if (peerInit) {
                wc_curve25519_free(&peer);
            }
        }
        else
#else
        if (ks->group == WN_GROUP_SECP256R1) {
            if (peerPubLen != WN_SECP256R1_PUB_SZ) {
                ret = WOLFNANOTLS_E_INVALID_ARG;
            }
            if ((ret == WOLFNANOTLS_SUCCESS) && (wc_ecc_init(&eccPeer) != 0)) {
                ret = WOLFNANOTLS_E_CRYPTO;
            }
            if (ret == WOLFNANOTLS_SUCCESS) {
                peerInit = 1;
                if (wc_ecc_import_x963_ex(peerPub, peerPubLen, &eccPeer,
                                          ECC_SECP256R1) != 0) {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
            }
            if (ret == WOLFNANOTLS_SUCCESS) {
                *outLen = WN_SECP256R1_SECRET_SZ;
                if (wc_ecc_shared_secret(&ks->ecc, &eccPeer, out, outLen) != 0) {
                    ret = WOLFNANOTLS_E_CRYPTO;
                }
            }
            if (peerInit) {
                wc_ecc_free(&eccPeer);
            }
        }
        else
#endif
        {
            ret = WOLFNANOTLS_E_UNSUPPORTED;
        }
    }

    return ret;
}

int wn_KeyShare_Free(wn_KeyShare* ks)
{
    int ret = WOLFNANOTLS_SUCCESS;

    if (ks == NULL) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }
#ifdef WOLFNANOTLS_HAVE_ECDHE_P256
    else if (ks->group == WN_GROUP_SECP256R1) {
        wc_ecc_free(&ks->ecc);
    }
#else
    else if (ks->group == WN_GROUP_X25519) {
        wc_curve25519_free(&ks->x25519);
    }
#endif

    return ret;
}
