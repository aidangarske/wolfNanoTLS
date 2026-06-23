/* clienthello_test.c
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

/* ClientHello encoder test: build, then parse the bytes back and confirm the
 * structure and that the key_share carries our X25519 public key. */

#include "wn_clienthello.h"
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

int main(void)
{
    byte rnd[32], sid[32], pub[32];
    byte ch[512];
    wn_Reader r;
    const byte* p;
    word32 chLen = 0;
    word32 hsLen, extEnd;
    word16 ver, csLen, extLen, et, el, ksLen, grp, klen;
    byte type, sidLen, compLen;
    int i, ksFound = 0, ksMatch = 0;
    int rc;

    for (i = 0; i < 32; i++) { rnd[i] = (byte)i; }
    for (i = 0; i < 32; i++) { sid[i] = (byte)(0x40 + i); }
    for (i = 0; i < 32; i++) { pub[i] = (byte)(0x80 + i); }

    printf("wolfNanoTLS ClientHello encoder test\n");

    rc = wn_ClientHello_Build(ch, &chLen, sizeof(ch), rnd, sid, 32, pub, 32);
    check((rc == WOLFNANOTLS_SUCCESS) && (chLen > 0), "build ClientHello");

    wn_Reader_Init(&r, ch, chLen);
    type  = wn_Read_U8(&r);
    hsLen = wn_Read_U24(&r);
    ver   = wn_Read_U16(&r);
    check((type == 1) && (hsLen == (chLen - 4)) && (ver == 0x0303),
          "handshake header + legacy_version");

    p = wn_Read_Bytes(&r, 32);                 /* random */
    check((p != NULL) && (XMEMCMP(p, rnd, 32) == 0), "random echoed");

    sidLen = wn_Read_U8(&r);
    p = wn_Read_Bytes(&r, sidLen);
    check((sidLen == 32) && (p != NULL) && (XMEMCMP(p, sid, 32) == 0),
          "legacy_session_id echoed");

    csLen = wn_Read_U16(&r);
    ver   = wn_Read_U16(&r);                    /* first cipher suite */
    check((csLen == 2) && (ver == WN_CIPHER_AES_128_GCM_SHA256),
          "cipher suite TLS_AES_128_GCM_SHA256");

    compLen = wn_Read_U8(&r);
    (void)wn_Read_U8(&r);
    check(compLen == 1, "legacy_compression_methods");

    extLen = wn_Read_U16(&r);
    extEnd = r.pos + extLen;
    if (extEnd > chLen) {                       /* bound the loop to the input */
        extEnd = chLen;
    }
    while ((r.pos < extEnd) && (r.err == 0)) {
        et = wn_Read_U16(&r);
        el = wn_Read_U16(&r);
        if (et == 51) {                        /* key_share */
            ksFound = 1;
            ksLen = wn_Read_U16(&r);
            grp   = wn_Read_U16(&r);
            klen  = wn_Read_U16(&r);
            p     = wn_Read_Bytes(&r, klen);
            if ((ksLen == 36) && (grp == 0x001d) && (klen == 32) &&
                (p != NULL) && (XMEMCMP(p, pub, 32) == 0)) {
                ksMatch = 1;
            }
        }
        else {
            (void)wn_Read_Bytes(&r, el);
        }
    }
    check(ksFound && ksMatch && (r.err == 0),
          "key_share carries our X25519 public key");

    /* invalid args + buffer too small */
    rc = wn_ClientHello_Build(NULL, &chLen, sizeof(ch), rnd, sid, 32, pub, 32);
    check(rc == WOLFNANOTLS_E_INVALID_ARG, "ClientHello NULL out rejected");
    rc = wn_ClientHello_Build(ch, &chLen, 16, rnd, sid, 32, pub, 32);
    check(rc == WOLFNANOTLS_E_INVALID_ARG, "ClientHello tiny buffer rejected");

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
