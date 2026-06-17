/* handshake_crypto_test.c
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

/* End-to-end cryptographic handshake: two in-process parties run ECDHE, the
 * full key schedule over a shared transcript, derive record keys, and exchange
 * AES-GCM protected records. Proves the shell modules compose into a working
 * TLS 1.3 crypto pipeline (no sockets / no wire encoding yet). */

#include "wn_keyshare.h"
#include "wn_keyschedule.h"
#include "wn_transcript.h"
#include "wn_record.h"
#include "wolfnano_crypto.h"
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
    }
}

int main(void)
{
    WC_RNG rng;
    wn_KeyShare cli, srv;
    wn_Transcript tc;
    byte cliPub[32], srvPub[32];
    byte ssA[32], ssB[32];
    byte th[48];
    byte emptyHash[32], early[32], derived[32], hs[32], cHs[32], sHs[32];
    byte cKey[16], cIv[12], sKey[16], sIv[12];
    byte rec[5 + 16 + 1 + 16];
    byte out[64];
    const byte ping[4] = { 'p','i','n','g' };
    const byte pong[4] = { 'p','o','n','g' };
    word32 cliPubLen = 0, srvPubLen = 0, ssALen = 0, ssBLen = 0, thLen = 0;
    word32 recLen = 0, outLen = 0;
    byte type = 0;
    int rc;

    printf("wolfNano end-to-end crypto handshake\n");

    rc = wc_InitRng(&rng);
    check(rc == 0, "RNG init");

    /* 1. ECDHE */
    rc  = wn_KeyShare_Init(&cli, WN_GROUP_X25519);
    rc |= wn_KeyShare_Init(&srv, WN_GROUP_X25519);
    rc |= wn_KeyShare_Generate(&cli, &rng, cliPub, &cliPubLen);
    rc |= wn_KeyShare_Generate(&srv, &rng, srvPub, &srvPubLen);
    rc |= wn_KeyShare_Shared(&cli, srvPub, srvPubLen, ssA, &ssALen);
    rc |= wn_KeyShare_Shared(&srv, cliPub, cliPubLen, ssB, &ssBLen);
    check((rc == WOLFNANO_SUCCESS) && (ssALen == 32) &&
          (XMEMCMP(ssA, ssB, 32) == 0), "ECDHE shared secret agrees");

    /* 2. transcript over the exchanged key shares (stand-in for CH..SH) */
    rc  = wn_Transcript_Init(&tc, WC_SHA256);
    rc |= wn_Transcript_Update(&tc, cliPub, cliPubLen);
    rc |= wn_Transcript_Update(&tc, srvPub, srvPubLen);
    rc |= wn_Transcript_GetHash(&tc, th, &thLen);
    rc |= wn_Transcript_Free(&tc);
    check((rc == WOLFNANO_SUCCESS) && (thLen == 32), "transcript hash computed");

    /* 3. key schedule to handshake traffic secrets */
    rc  = wc_Sha256Hash((const byte*)"", 0, emptyHash);
    rc |= wn_Tls13_Extract(early, NULL, 0, emptyHash, 32, WC_SHA256);
    rc |= wn_Tls13_DeriveSecret(derived, early, "derived", emptyHash, 32,
                                WC_SHA256);
    rc |= wn_Tls13_Extract(hs, derived, 32, ssA, 32, WC_SHA256);
    rc |= wn_Tls13_DeriveSecret(cHs, hs, "c hs traffic", th, 32, WC_SHA256);
    rc |= wn_Tls13_DeriveSecret(sHs, hs, "s hs traffic", th, 32, WC_SHA256);
    check(rc == WOLFNANO_SUCCESS, "derive handshake traffic secrets");

    /* 4. record keys from each traffic secret */
    rc  = wn_Tls13_ExpandLabel(cKey, sizeof(cKey), cHs, "key", NULL, 0,
                               WC_SHA256);
    rc |= wn_Tls13_ExpandLabel(cIv, sizeof(cIv), cHs, "iv", NULL, 0, WC_SHA256);
    rc |= wn_Tls13_ExpandLabel(sKey, sizeof(sKey), sHs, "key", NULL, 0,
                               WC_SHA256);
    rc |= wn_Tls13_ExpandLabel(sIv, sizeof(sIv), sHs, "iv", NULL, 0, WC_SHA256);
    check(rc == WOLFNANO_SUCCESS, "derive record key/iv");

    /* 5. client -> server protected record */
    rc  = wn_Record_Protect(rec, &recLen, cKey, sizeof(cKey), cIv, 0, 23,
                            ping, sizeof(ping));
    rc |= wn_Record_Unprotect(out, &outLen, &type, cKey, sizeof(cKey), cIv, 0,
                              rec, recLen);
    check((rc == WOLFNANO_SUCCESS) && (outLen == 4) && (type == 23) &&
          (XMEMCMP(out, ping, 4) == 0), "client->server record round-trips");

    /* 6. server -> client protected record */
    rc  = wn_Record_Protect(rec, &recLen, sKey, sizeof(sKey), sIv, 0, 23,
                            pong, sizeof(pong));
    rc |= wn_Record_Unprotect(out, &outLen, &type, sKey, sizeof(sKey), sIv, 0,
                              rec, recLen);
    check((rc == WOLFNANO_SUCCESS) && (outLen == 4) && (type == 23) &&
          (XMEMCMP(out, pong, 4) == 0), "server->client record round-trips");

    wn_KeyShare_Free(&cli);
    wn_KeyShare_Free(&srv);
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
