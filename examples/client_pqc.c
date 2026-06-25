/* client_pqc.c
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
 * Minimal wolfNanoTLS TLS 1.3 client: external-PSK handshake over the
 * X25519MLKEM768 post-quantum hybrid group, then one application-data round
 * trip and a clean close. The hybrid group is selected at compile time by the
 * PQC config (WOLFNANOTLS_HAVE_MLKEM_HYBRID), so this mirrors the PSK example.
 * Lifecycle: wn_Connect_Psk_ex -> wn_Send -> wn_Recv -> wn_Close.
 *
 * Usage: client_pqc <host> <port>   (default 127.0.0.1 4433)
 * Try it against wolfSSL's example server (built with --enable-mlkem):
 *   examples/server/server -v 4 -s -i --pqc X25519MLKEM768 -p 4433
 */

#include "wn_connect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char** argv)
{
    /* wolfSSL's example server (-s) uses this fixed TLS 1.3 PSK for identity
     * "Client_identity": 01 23 45 67 89 ab cd ef, repeated. */
    static const byte psk[32] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    static const byte msg[] = "hello from wolfNanoTLS\n";
    const char* host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 4433;
    struct sockaddr_in sa;
    WC_RNG rng;
    wn_Session sess;
    byte scratch[8192];
    byte in[512];
    word32 got = 0;
    int fd, rc;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket failed\n");
        return 1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        printf("connect to %s:%d failed\n", host, port);
        close(fd);
        return 1;
    }

    if (wc_InitRng(&rng) != 0) {
        printf("rng init failed\n");
        close(fd);
        return 1;
    }

    rc = wn_Connect_Psk_ex(&sess, &rng, sock_send, sock_recv, &fd, psk,
                           (word32)sizeof(psk), "Client_identity", scratch,
                           sizeof(scratch));
    if (rc != 0) {
        printf("handshake failed: %d\n", rc);
        wc_FreeRng(&rng);
        close(fd);
        return 1;
    }
    printf("TLS 1.3 hybrid handshake complete\n");

    rc = wn_Send(&sess, msg, (word32)(sizeof(msg) - 1));
    if (rc == 0) {
        rc = wn_Recv(&sess, in, sizeof(in), &got);
    }
    if (rc == 0) {
        printf("received %u bytes: %.*s\n", (unsigned)got, (int)got, in);
    }
    else {
        printf("application data failed: %d\n", rc);
    }

    wn_Close(&sess);
    wc_FreeRng(&rng);
    close(fd);

    return (rc == 0) ? 0 : 1;
}
