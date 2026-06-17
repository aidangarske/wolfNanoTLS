/* wn_keyshare.c
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
 * TLS 1.3 X25519 key share over the wc_* seam. Wire format is little-endian
 * (RFC 7748). Ported from wolfSSL curve25519 usage; caller-held context.
 */

#include "wn_keyshare.h"

int wn_KeyShare_Init(wn_KeyShare* ks, int group)
{
    int ret = WOLFNANO_SUCCESS;

    if (ks == NULL) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    else if (group != WN_GROUP_X25519) {
        ret = WOLFNANO_E_UNSUPPORTED;
    }

    if (ret == WOLFNANO_SUCCESS) {
        ks->group = group;
        if (wc_curve25519_init(&ks->x25519) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    return ret;
}

int wn_KeyShare_Generate(wn_KeyShare* ks, WC_RNG* rng, byte* pub,
                         word32* pubLen)
{
    int ret = WOLFNANO_SUCCESS;

    if ((ks == NULL) || (rng == NULL) || (pub == NULL) || (pubLen == NULL)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        if (wc_curve25519_make_key(rng, WN_X25519_KEY_SZ, &ks->x25519) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    if (ret == WOLFNANO_SUCCESS) {
        *pubLen = WN_X25519_KEY_SZ;
        if (wc_curve25519_export_public_ex(&ks->x25519, pub, pubLen,
                                           EC25519_LITTLE_ENDIAN) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    return ret;
}

int wn_KeyShare_Shared(wn_KeyShare* ks, const byte* peerPub, word32 peerPubLen,
                       byte* out, word32* outLen)
{
    curve25519_key peer;
    int ret = WOLFNANO_SUCCESS;
    int peerInit = 0;

    if ((ks == NULL) || (peerPub == NULL) || (out == NULL) ||
        (outLen == NULL) || (peerPubLen != WN_X25519_KEY_SZ)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        if (wc_curve25519_init(&peer) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    if (ret == WOLFNANO_SUCCESS) {
        peerInit = 1;
        if (wc_curve25519_import_public_ex(peerPub, peerPubLen, &peer,
                                           EC25519_LITTLE_ENDIAN) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    if (ret == WOLFNANO_SUCCESS) {
        *outLen = WN_X25519_KEY_SZ;
        if (wc_curve25519_shared_secret_ex(&ks->x25519, &peer, out, outLen,
                                           EC25519_LITTLE_ENDIAN) != 0) {
            ret = WOLFNANO_E_CRYPTO;
        }
    }

    if (peerInit) {
        wc_curve25519_free(&peer);
    }

    return ret;
}

int wn_KeyShare_Free(wn_KeyShare* ks)
{
    int ret = WOLFNANO_SUCCESS;

    if (ks == NULL) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    else {
        wc_curve25519_free(&ks->x25519);
    }

    return ret;
}
