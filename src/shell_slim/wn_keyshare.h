/* wn_keyshare.h
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
 * TLS 1.3 (EC)DHE key share (RFC 8446 section 4.2.8). X25519 over the wc_* seam.
 * Caller holds the context; no allocation.
 */

#ifndef WN_KEYSHARE_H
#define WN_KEYSHARE_H

#include "wolfnano.h"
#include "wolfnano_crypto.h"

/* TLS supported_groups code points. */
#define WN_GROUP_X25519 0x001d

#define WN_X25519_KEY_SZ 32

typedef struct wn_KeyShare {
    curve25519_key x25519;
    int group;
} wn_KeyShare;

/* Initialise a key share for the given group. */
WOLFNANO_API int wn_KeyShare_Init(wn_KeyShare* ks, int group);

/* Generate the ephemeral key pair; pub receives the wire-format public key
 * (little-endian for X25519), pubLen its length. */
WOLFNANO_API int wn_KeyShare_Generate(wn_KeyShare* ks, WC_RNG* rng,
                                      byte* pub, word32* pubLen);

/* Compute the shared secret from the peer public key. */
WOLFNANO_API int wn_KeyShare_Shared(wn_KeyShare* ks, const byte* peerPub,
                                    word32 peerPubLen, byte* out,
                                    word32* outLen);

/* Release the key share. */
WOLFNANO_API int wn_KeyShare_Free(wn_KeyShare* ks);

#endif /* WN_KEYSHARE_H */
