/* wn_hybrid.h
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
 * TLS 1.3 X25519MLKEM768 hybrid key share (group 0x11ec,
 * draft-kwiatkowski-tls-ecdhe-mlkem). Concatenation is ML-KEM component first,
 * then X25519, for the shares and the combined secret. Over the wc_* seam,
 * caller-held context, no allocation. Requires WOLFNANO_MLKEM.
 */

#ifndef WN_HYBRID_H
#define WN_HYBRID_H

#include "wolfnano.h"
#include "wolfnano_crypto.h"
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#define WN_GROUP_X25519MLKEM768   0x11ec

#define WN_HYBRID_MLKEM_PUB   WC_ML_KEM_768_PUBLIC_KEY_SIZE   /* 1184 */
#define WN_HYBRID_MLKEM_CT    WC_ML_KEM_768_CIPHER_TEXT_SIZE  /* 1088 */
#define WN_HYBRID_X25519      32
#define WN_HYBRID_CLIENT_SHARE (WN_HYBRID_MLKEM_PUB + WN_HYBRID_X25519)
#define WN_HYBRID_SERVER_SHARE (WN_HYBRID_MLKEM_CT + WN_HYBRID_X25519)
#define WN_HYBRID_SECRET       (WC_ML_KEM_SS_SZ + WN_HYBRID_X25519)  /* 64 */

typedef struct wn_Hybrid {
    MlKemKey kem;
    curve25519_key x;
    int kemInit;                /* kem initialized (free-safe gate) */
    int xInit;                  /* x initialized  (free-safe gate) */
} wn_Hybrid;

/* Client: produce the key_share (ML-KEM public || X25519 public) and keep the
 * private state in h. */
WOLFNANO_API int wn_Hybrid_ClientKeyShare(wn_Hybrid* h, WC_RNG* rng,
                                          byte* out, word32* outLen);

/* Client: from the server share (ML-KEM ciphertext || X25519 public), derive
 * the combined secret (ML-KEM ss || X25519 ss). */
WOLFNANO_API int wn_Hybrid_ClientShared(wn_Hybrid* h, const byte* srvShare,
                                        word32 srvLen, byte* ss, word32* ssLen);

/* Server side (for testing): respond to a client share, producing the server
 * share and the same combined secret. */
WOLFNANO_API int wn_Hybrid_ServerRespond(const byte* cliShare, word32 cliLen,
                                         WC_RNG* rng, byte* srvShare,
                                         word32* srvLen, byte* ss,
                                         word32* ssLen);

WOLFNANO_API int wn_Hybrid_Free(wn_Hybrid* h);

#endif /* WN_HYBRID_H */
