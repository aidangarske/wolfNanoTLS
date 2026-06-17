/* keyshare_test.c
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

/* X25519 key-share tests: ephemeral agreement and public-key wire length. */

#include "wn_keyshare.h"
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
    wn_KeyShare a, b;
    byte pubA[WN_X25519_KEY_SZ], pubB[WN_X25519_KEY_SZ];
    byte sa[WN_X25519_KEY_SZ], sb[WN_X25519_KEY_SZ];
    word32 pubALen = 0, pubBLen = 0, saLen = 0, sbLen = 0;
    int rc;

    printf("wolfNano X25519 key-share tests\n");

    rc = wc_InitRng(&rng);
    check(rc == 0, "RNG init");

    rc  = wn_KeyShare_Init(&a, WN_GROUP_X25519);
    rc |= wn_KeyShare_Init(&b, WN_GROUP_X25519);
    rc |= wn_KeyShare_Generate(&a, &rng, pubA, &pubALen);
    rc |= wn_KeyShare_Generate(&b, &rng, pubB, &pubBLen);
    check((rc == WOLFNANO_SUCCESS) && (pubALen == 32) && (pubBLen == 32),
          "generate two key shares, 32-byte public keys");

    rc  = wn_KeyShare_Shared(&a, pubB, pubBLen, sa, &saLen);
    rc |= wn_KeyShare_Shared(&b, pubA, pubALen, sb, &sbLen);
    check((rc == WOLFNANO_SUCCESS) && (saLen == 32) && (sbLen == 32) &&
          (XMEMCMP(sa, sb, 32) == 0), "ECDHE shared secrets agree");

    rc = wn_KeyShare_Init(&a, 0x0017);
    check(rc == WOLFNANO_E_UNSUPPORTED, "unsupported group is rejected");

    wn_KeyShare_Free(&a);
    wn_KeyShare_Free(&b);
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
