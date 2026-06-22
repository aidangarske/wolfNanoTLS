/* hybrid_test.c
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

/* X25519MLKEM768 hybrid key share: client and server derive the same secret. */

#include "wn_hybrid.h"
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

int main(void)
{
    WC_RNG rng;
    wn_Hybrid h;
    byte cliShare[WN_HYBRID_CLIENT_SHARE];
    byte srvShare[WN_HYBRID_SERVER_SHARE];
    byte ssC[WN_HYBRID_SECRET], ssS[WN_HYBRID_SECRET];
    word32 cliLen = 0, srvLen = 0, ssCLen = 0, ssSLen = 0;
    int rc;

    printf("wolfNanoTLS X25519MLKEM768 hybrid key-share test\n");

    rc = wc_InitRng(&rng);
    check(rc == 0, "RNG init");

    rc = wn_Hybrid_ClientKeyShare(&h, &rng, cliShare, &cliLen);
    check((rc == WOLFNANOTLS_SUCCESS) && (cliLen == WN_HYBRID_CLIENT_SHARE),
          "client key_share (ML-KEM pub || X25519 pub)");

    rc = wn_Hybrid_ServerRespond(cliShare, cliLen, &rng, srvShare, &srvLen,
                                 ssS, &ssSLen);
    check((rc == WOLFNANOTLS_SUCCESS) && (srvLen == WN_HYBRID_SERVER_SHARE) &&
          (ssSLen == WN_HYBRID_SECRET),
          "server respond (ciphertext || X25519 pub)");

    rc = wn_Hybrid_ClientShared(&h, srvShare, srvLen, ssC, &ssCLen);
    check((rc == WOLFNANOTLS_SUCCESS) && (ssCLen == WN_HYBRID_SECRET),
          "client derive combined secret");

    check((ssCLen == ssSLen) && (XMEMCMP(ssC, ssS, WN_HYBRID_SECRET) == 0),
          "hybrid secrets agree (64 bytes)");

    /* NULL / invalid-arg paths */
    check(wn_Hybrid_ClientKeyShare(NULL, &rng, cliShare, &cliLen)
          == WOLFNANOTLS_E_INVALID_ARG, "ClientKeyShare NULL rejected");
    check(wn_Hybrid_ClientShared(&h, srvShare, 1, ssC, &ssCLen)
          == WOLFNANOTLS_E_INVALID_ARG, "ClientShared bad length rejected");
    check(wn_Hybrid_ServerRespond(cliShare, 1, &rng, srvShare, &srvLen,
          ssS, &ssSLen) == WOLFNANOTLS_E_INVALID_ARG,
          "ServerRespond bad length rejected");
    check(wn_Hybrid_Free(NULL) == WOLFNANOTLS_E_INVALID_ARG, "Free NULL rejected");

    /* malformed client ML-KEM public key: decode rejects it */
    XMEMSET(cliShare, 0xff, WN_HYBRID_MLKEM_PUB);
    check(wn_Hybrid_ServerRespond(cliShare, WN_HYBRID_CLIENT_SHARE, &rng,
          srvShare, &srvLen, ssS, &ssSLen) != WOLFNANOTLS_SUCCESS,
          "ServerRespond rejects malformed client ML-KEM key");

    wn_Hybrid_Free(&h);
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
