/* suites_matrix.c
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
 * Data-driven negotiation matrix: for every supported (cipher suite x key-share
 * group x PSK/cert) combination wolfNano can negotiate, encode a ServerHello
 * with those parameters and assert wn_ServerHello_Parse recovers them exactly.
 * Pure shell-level (no network), exercising the negotiation-relevant parsing
 * across the whole kept parameter space in one table.
 */

#include "wn_serverhello.h"
#include "wn_msg.h"
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

typedef struct {
    const char* name;
    word16 cipher;
    word16 group;
    word16 keyLen;     /* server key_share length for the group */
    int    psk;        /* 1 = include pre_shared_key (selected_identity 0) */
} wn_Case;

/* Build a minimal but well-formed TLS 1.3 ServerHello with the given
 * negotiated parameters. Returns the encoded length. */
static word32 build_sh(byte* buf, word32 cap, const wn_Case* c)
{
    wn_Writer w;
    word32 hsLen, extLen;
    byte zero[1120];               /* >= largest key share (x25519mlkem768) */
    int i;

    for (i = 0; i < (int)sizeof(zero); i++) {
        zero[i] = (byte)i;
    }

    wn_Writer_Init(&w, buf, cap);
    wn_Write_U8(&w, 2);                          /* ServerHello */
    hsLen = wn_Write_LenStart(&w, 3);
    wn_Write_U16(&w, 0x0303);                    /* legacy_version */
    wn_Write_Bytes(&w, zero, 32);               /* random */
    wn_Write_U8(&w, 0);                          /* legacy_session_id_echo len */
    wn_Write_U16(&w, c->cipher);
    wn_Write_U8(&w, 0);                          /* compression */

    extLen = wn_Write_LenStart(&w, 2);
    wn_Write_U16(&w, 43);                        /* supported_versions */
    wn_Write_U16(&w, 2);
    wn_Write_U16(&w, 0x0304);
    wn_Write_U16(&w, 51);                        /* key_share */
    wn_Write_U16(&w, (word16)(4 + c->keyLen));
    wn_Write_U16(&w, c->group);
    wn_Write_U16(&w, c->keyLen);
    wn_Write_Bytes(&w, zero, c->keyLen);
    if (c->psk) {
        wn_Write_U16(&w, 41);                    /* pre_shared_key */
        wn_Write_U16(&w, 2);
        wn_Write_U16(&w, 0);                     /* selected_identity */
    }
    wn_Write_LenEnd(&w, extLen, 2);
    wn_Write_LenEnd(&w, hsLen, 3);

    return w.len;
}

int main(void)
{
    static const wn_Case cases[] = {
        { "AES128-GCM-SHA256 / X25519 / cert", 0x1301, 0x001d, 32, 0 },
        { "AES128-GCM-SHA256 / X25519 / PSK",  0x1301, 0x001d, 32, 1 },
        { "AES128-GCM-SHA256 / P-256  / cert", 0x1301, 0x0017, 65, 0 },
        { "AES128-GCM-SHA256 / P-256  / PSK",  0x1301, 0x0017, 65, 1 },
        { "AES256-GCM-SHA384 / P-256  / cert", 0x1302, 0x0017, 65, 0 },
        { "AES256-GCM-SHA384 / X25519 / PSK",  0x1302, 0x001d, 32, 1 },
        { "AES128-GCM-SHA256 / x25519mlkem768", 0x1301, 0x11ec, 1120, 0 }
    };
    byte buf[2048];
    wn_ServerHello sh;
    word32 n;
    int i;
    int rc;
    int ok;

    printf("wolfNano negotiation matrix (ServerHello parse round-trip)\n");

    for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        n = build_sh(buf, (word32)sizeof(buf), &cases[i]);
        rc = wn_ServerHello_Parse(buf, n, &sh);
        ok = (rc == WOLFNANO_SUCCESS) &&
             (sh.cipher == cases[i].cipher) &&
             (sh.group == cases[i].group) &&
             (sh.version == 0x0304) &&
             (sh.keyShareLen == cases[i].keyLen) &&
             (sh.keyShare != NULL) &&
             (cases[i].psk ? (sh.pskSelected == 0) : (sh.pskSelected == -1));
        check(ok, cases[i].name);
    }

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
