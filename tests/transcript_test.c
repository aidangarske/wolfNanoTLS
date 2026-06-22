/* transcript_test.c
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

/* Transcript-hash tests: incremental correctness, non-destructive interim
 * digest, SHA-256 and SHA-384 (FIPS 180-4 "abc" vectors). */

#include "wn_transcript.h"
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

static int eq(const byte* a, const byte* b, word32 n)
{
    return XMEMCMP(a, b, n) == 0;
}

int main(void)
{
    static const byte sha256abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    static const byte sha384abc[48] = {
        0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
        0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
        0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7
    };
    wn_Transcript t;
    byte h1[48], h2[48];
    word32 l1 = 0, l2 = 0;
    int rc;

    printf("wolfNanoTLS transcript-hash tests\n");

    rc  = wn_Transcript_Init(&t, WC_SHA256);
    rc |= wn_Transcript_Update(&t, (const byte*)"abc", 3);
    rc |= wn_Transcript_GetHash(&t, h1, &l1);
    rc |= wn_Transcript_Free(&t);
    check((rc == WOLFNANOTLS_SUCCESS) && (l1 == 32) && eq(h1, sha256abc, 32),
          "SHA-256 transcript of \"abc\"");

    rc  = wn_Transcript_Init(&t, WC_SHA256);
    rc |= wn_Transcript_Update(&t, (const byte*)"ab", 2);
    rc |= wn_Transcript_Update(&t, (const byte*)"c", 1);
    rc |= wn_Transcript_GetHash(&t, h2, &l2);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(h2, sha256abc, 32),
          "incremental update matches one-shot");

    /* interim digest is non-destructive: a second GetHash with no update is
     * identical, and continuing to add data changes the running hash. */
    rc  = wn_Transcript_GetHash(&t, h1, &l1);
    check((rc == WOLFNANOTLS_SUCCESS) && eq(h1, h2, 32),
          "interim GetHash is non-destructive");
    rc  = wn_Transcript_Update(&t, (const byte*)"d", 1);
    rc |= wn_Transcript_GetHash(&t, h1, &l1);
    rc |= wn_Transcript_Free(&t);
    check((rc == WOLFNANOTLS_SUCCESS) && !eq(h1, h2, 32),
          "transcript continues after interim GetHash");

    rc  = wn_Transcript_Init(&t, WC_SHA384);
    rc |= wn_Transcript_Update(&t, (const byte*)"abc", 3);
    rc |= wn_Transcript_GetHash(&t, h1, &l1);
    rc |= wn_Transcript_Free(&t);
    check((rc == WOLFNANOTLS_SUCCESS) && (l1 == 48) && eq(h1, sha384abc, 48),
          "SHA-384 transcript of \"abc\"");

    /* NULL args rejected */
    check(wn_Transcript_Init(NULL, WC_SHA256) == WOLFNANOTLS_E_INVALID_ARG,
          "Init NULL rejected");
    check(wn_Transcript_Update(NULL, h1, 1) == WOLFNANOTLS_E_INVALID_ARG,
          "Update NULL rejected");
    check(wn_Transcript_GetHash(NULL, h1, &l1) == WOLFNANOTLS_E_INVALID_ARG,
          "GetHash NULL rejected");
    check(wn_Transcript_Free(NULL) == WOLFNANOTLS_E_INVALID_ARG,
          "Free NULL rejected");

    /* unsupported digest rejected in init, update, get-hash */
    rc = wn_Transcript_Init(&t, 0x7f);
    check(rc == WOLFNANOTLS_E_UNSUPPORTED, "Init unsupported digest");
    check(wn_Transcript_Update(&t, h1, 1) == WOLFNANOTLS_E_UNSUPPORTED,
          "Update unsupported digest");
    check(wn_Transcript_GetHash(&t, h1, &l1) == WOLFNANOTLS_E_UNSUPPORTED,
          "GetHash unsupported digest");

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
