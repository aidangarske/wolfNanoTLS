/* noalloc_probe_test.c
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
 * Runtime proof of the zero-allocation guarantee: run the full handshake crypto
 * path (ECDHE, key schedule, transcript, AES-GCM record protect/unprotect) with
 * the malloc trap armed and assert it made zero heap allocations. Complements
 * the static nm/grep no-alloc checks with a dynamic one. No stdio runs while
 * the trap is armed. Built with the --wrap interposer in noalloc_probe.c.
 */

#include "wn_keyshare.h"
#include "wn_keyschedule.h"
#include "wn_transcript.h"
#include "wn_record.h"
#include "wolfnano_crypto.h"
#include <stdio.h>

extern int wn_alloc_watch;
extern unsigned long wn_alloc_count;

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
    word32 cliPubLen = 0, srvPubLen = 0, ssALen = 0, ssBLen = 0, thLen = 0;
    word32 recLen = 0, outLen = 0;
    byte type = 0;
    int rc;
    int ok;

    printf("wolfNanoTLS runtime no-malloc trap (handshake crypto path)\n");

    wn_alloc_watch = 1;

    rc  = wc_InitRng(&rng);
    rc |= wn_KeyShare_Init(&cli, WN_GROUP_X25519);
    rc |= wn_KeyShare_Init(&srv, WN_GROUP_X25519);
    rc |= wn_KeyShare_Generate(&cli, &rng, cliPub, &cliPubLen);
    rc |= wn_KeyShare_Generate(&srv, &rng, srvPub, &srvPubLen);
    rc |= wn_KeyShare_Shared(&cli, srvPub, srvPubLen, ssA, &ssALen);
    rc |= wn_KeyShare_Shared(&srv, cliPub, cliPubLen, ssB, &ssBLen);
    rc |= wn_Transcript_Init(&tc, WC_SHA256);
    rc |= wn_Transcript_Update(&tc, cliPub, cliPubLen);
    rc |= wn_Transcript_Update(&tc, srvPub, srvPubLen);
    rc |= wn_Transcript_GetHash(&tc, th, &thLen);
    rc |= wn_Transcript_Free(&tc);
    rc |= wc_Sha256Hash((const byte*)"", 0, emptyHash);
    rc |= wn_Tls13_Extract(early, NULL, 0, emptyHash, 32, WC_SHA256);
    rc |= wn_Tls13_DeriveSecret(derived, early, "derived", emptyHash, 32,
                                WC_SHA256);
    rc |= wn_Tls13_Extract(hs, derived, 32, ssA, 32, WC_SHA256);
    rc |= wn_Tls13_DeriveSecret(cHs, hs, "c hs traffic", th, 32, WC_SHA256);
    rc |= wn_Tls13_DeriveSecret(sHs, hs, "s hs traffic", th, 32, WC_SHA256);
    rc |= wn_Tls13_ExpandLabel(cKey, sizeof(cKey), cHs, "key", NULL, 0,
                               WC_SHA256);
    rc |= wn_Tls13_ExpandLabel(cIv, sizeof(cIv), cHs, "iv", NULL, 0, WC_SHA256);
    rc |= wn_Tls13_ExpandLabel(sKey, sizeof(sKey), sHs, "key", NULL, 0,
                               WC_SHA256);
    rc |= wn_Tls13_ExpandLabel(sIv, sizeof(sIv), sHs, "iv", NULL, 0, WC_SHA256);
    rc |= wn_Record_Protect(rec, &recLen, cKey, sizeof(cKey), cIv, 0, 23,
                            ping, sizeof(ping));
    rc |= wn_Record_Unprotect(out, &outLen, &type, cKey, sizeof(cKey), cIv, 0,
                              rec, recLen);

    wn_KeyShare_Free(&cli);
    wn_KeyShare_Free(&srv);
    wc_FreeRng(&rng);

    wn_alloc_watch = 0;

    ok = (rc == WOLFNANO_SUCCESS) && (outLen == 4) && (type == 23) &&
         (XMEMCMP(out, ping, 4) == 0);

    printf("%s handshake crypto path succeeded\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m");
    printf("%s zero heap allocations (%lu observed)\n",
           (wn_alloc_count == 0) ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m",
           wn_alloc_count);

    printf("\n%s\n", (ok && (wn_alloc_count == 0)) ? "\033[32mALL PASS (0 failures)\033[0m"
                                                 : "\033[31mFAILED\033[0m");
    return (ok && (wn_alloc_count == 0)) ? 0 : 1;
}
