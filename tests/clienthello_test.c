/* clienthello_test.c
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
    static const char host[] = "example.com";
    char longhost[301];
    word16 listLen, nameLen;
    byte nameType;
    int sniFound = 0, sniMatch = 0, sniAbsent = 1;

    for (i = 0; i < 32; i++) { rnd[i] = (byte)i; }
    for (i = 0; i < 32; i++) { sid[i] = (byte)(0x40 + i); }
    for (i = 0; i < 32; i++) { pub[i] = (byte)(0x80 + i); }

    printf("wolfNano ClientHello encoder test\n");

    rc = wn_ClientHello_Build(ch, &chLen, sizeof(ch), rnd, sid, 32, pub, 32);
    check((rc == WOLFNANO_SUCCESS) && (chLen > 0), "build ClientHello");

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
            if (et == 0) {                     /* server_name */
                sniAbsent = 0;
            }
            (void)wn_Read_Bytes(&r, el);
        }
    }
    check(ksFound && ksMatch && (r.err == 0),
          "key_share carries our X25519 public key");
    check(sniAbsent, "no server_name extension when serverName is NULL");

    /* build again with SNI and confirm the server_name extension is present */
    rc = wn_ClientHello_Build_ex(ch, &chLen, sizeof(ch), rnd, sid, 32, pub, 32,
                                 host);
    check(rc == WOLFNANO_SUCCESS, "build ClientHello with SNI");
    wn_Reader_Init(&r, ch, chLen);
    (void)wn_Read_U8(&r); (void)wn_Read_U24(&r); (void)wn_Read_U16(&r);
    (void)wn_Read_Bytes(&r, 32);
    sidLen = wn_Read_U8(&r); (void)wn_Read_Bytes(&r, sidLen);
    (void)wn_Read_U16(&r); (void)wn_Read_U16(&r);          /* cipher_suites */
    compLen = wn_Read_U8(&r); (void)wn_Read_Bytes(&r, compLen);
    extLen = wn_Read_U16(&r);
    extEnd = r.pos + extLen;
    if (extEnd > chLen) { extEnd = chLen; }
    while ((r.pos < extEnd) && (r.err == 0)) {
        et = wn_Read_U16(&r);
        el = wn_Read_U16(&r);
        if (et == 0) {                         /* server_name */
            sniFound = 1;
            listLen  = wn_Read_U16(&r);
            nameType = wn_Read_U8(&r);
            nameLen  = wn_Read_U16(&r);
            p        = wn_Read_Bytes(&r, nameLen);
            if ((listLen == (word16)(1 + 2 + (sizeof(host) - 1))) &&
                (nameType == 0) && (nameLen == (sizeof(host) - 1)) &&
                (p != NULL) && (XMEMCMP(p, host, sizeof(host) - 1) == 0)) {
                sniMatch = 1;
            }
        }
        else {
            (void)wn_Read_Bytes(&r, el);
        }
    }
    check(sniFound && sniMatch && (r.err == 0),
          "server_name (SNI) carries the host name");

    /* exactly 255 bytes is the maximum accepted host length */
    for (i = 0; i < 255; i++) { longhost[i] = 'a'; }
    longhost[255] = 0;
    rc = wn_ClientHello_Build_ex(ch, &chLen, sizeof(ch), rnd, sid, 32, pub, 32,
                                 longhost);
    check(rc == WOLFNANO_SUCCESS, "255-byte SNI host accepted");

    /* 256 bytes is the first length over the limit */
    for (i = 0; i < 256; i++) { longhost[i] = 'a'; }
    longhost[256] = 0;
    rc = wn_ClientHello_Build_ex(ch, &chLen, sizeof(ch), rnd, sid, 32, pub, 32,
                                 longhost);
    check(rc == WOLFNANO_E_INVALID_ARG, "256-byte SNI host rejected");

    /* SNI host longer than the 255-byte limit is rejected */
    for (i = 0; i < 300; i++) { longhost[i] = 'a'; }
    longhost[300] = 0;
    rc = wn_ClientHello_Build_ex(ch, &chLen, sizeof(ch), rnd, sid, 32, pub, 32,
                                 longhost);
    check(rc == WOLFNANO_E_INVALID_ARG, "over-long SNI host rejected");

    /* invalid args + buffer too small */
    rc = wn_ClientHello_Build(NULL, &chLen, sizeof(ch), rnd, sid, 32, pub, 32);
    check(rc == WOLFNANO_E_INVALID_ARG, "ClientHello NULL out rejected");
    rc = wn_ClientHello_Build(ch, &chLen, 16, rnd, sid, 32, pub, 32);
    check(rc == WOLFNANO_E_INVALID_ARG, "ClientHello tiny buffer rejected");

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
