/* interop_psk_test.c
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

/* Live interop: wolfNanoTLS TLS 1.3 PSK+ECDHE client against openssl s_server. */

#include "wn_connect.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int sock_send(void* ctx, const byte* buf, word32 len)
{
    return (int)send(*(int*)ctx, buf, len, 0);
}

static int sock_recv(void* ctx, byte* buf, word32 len)
{
    return (int)recv(*(int*)ctx, buf, len, 0);
}

static int hexval(char c)
{
    int v = -1;

    if ((c >= '0') && (c <= '9')) {
        v = c - '0';
    }
    else if ((c >= 'a') && (c <= 'f')) {
        v = c - 'a' + 10;
    }
    else if ((c >= 'A') && (c <= 'F')) {
        v = c - 'A' + 10;
    }

    return v;
}

static word32 hex2bin(const char* hex, byte* out, word32 maxOut)
{
    word32 n = 0;
    int hi, lo;

    while ((hex[0] != '\0') && (hex[1] != '\0') && (n < maxOut)) {
        hi = hexval(hex[0]);
        lo = hexval(hex[1]);
        if ((hi < 0) || (lo < 0)) {
            break;
        }
        out[n] = (byte)((hi << 4) | lo);
        n++;
        hex += 2;
    }

    return n;
}

int main(int argc, char** argv)
{
    static const char* defHex = "000102030405060708090a0b0c0d0e0f";
    byte psk[64];
    const char* identity;
    word32 pskLen;
    struct sockaddr_in sa;
    WC_RNG rng;
    wn_Session sess;
    byte scratch[8192];
    int fd, port, rc, tries;

    port = (argc > 1) ? atoi(argv[1]) : 4433;
    pskLen = hex2bin((argc > 2) ? argv[2] : defHex, psk, sizeof(psk));
    identity = (argc > 3) ? argv[3] : "Client_identity";

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket failed\n");
        return 2;
    }
    XMEMSET(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    rc = -1;
    tries = 0;
    while ((tries < 50) && (rc != 0)) {
        rc = connect(fd, (struct sockaddr*)&sa, sizeof(sa));
        if (rc != 0) {
            usleep(50000);
            tries++;
        }
    }
    if (rc != 0) {
        printf("connect failed\n");
        return 2;
    }

    if (wc_InitRng(&rng) != 0) {
        printf("rng failed\n");
        return 2;
    }

    rc = wn_Connect_Psk_ex(&sess, &rng, sock_send, sock_recv, &fd, psk, pskLen,
                           identity, scratch, sizeof(scratch));

    printf("wn_Connect_Psk = %d\n", rc);
    printf("%s\n", (rc == 0) ? "PASS TLS 1.3 PSK handshake"
                             : "FAIL handshake");

    /* Optional application-data round trip (WN_APPDATA=1, e.g. vs
     * `openssl s_server -rev` which echoes each line reversed). */
    if ((rc == 0) && (getenv("WN_APPDATA") != NULL)) {
        static const byte msg[] = "wolfNanoTLS\n";
        byte in[256];
        word32 got = 0;
        int arc;

        arc = wn_Send(&sess, msg, (word32)(sizeof(msg) - 1));
        if (arc == 0) {
            arc = wn_Recv(&sess, in, sizeof(in), &got);
        }
        printf("app-data rc = %d, got %u bytes\n", arc, (unsigned)got);
        printf("%s\n", ((arc == 0) && (got > 0)) ? "PASS app-data round trip"
                                                 : "FAIL app-data");
        if ((arc != 0) || (got == 0)) {
            rc = 1;
        }
        (void)wn_Close(&sess);
    }
    else if (rc == 0) {
        (void)wn_Close(&sess);
    }

    wc_FreeRng(&rng);
    close(fd);

    return (rc == 0) ? 0 : 1;
}
