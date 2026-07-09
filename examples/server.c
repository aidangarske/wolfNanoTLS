/* server.c
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
 * Minimal wolfNanoTLS TLS 1.3 server: external-PSK + ECDHE handshake, then it
 * echoes one application-data record and closes. Lifecycle: accept ->
 * wn_Accept_Psk_ex -> wn_Recv -> wn_Send -> wn_Close.
 *
 * Usage: server <port>   (default 4433)
 * Try it against the wolfNanoTLS client (examples/client.c) or OpenSSL:
 *   openssl s_client -tls1_3 -psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -connect 127.0.0.1:4433
 */

#include "wn_accept.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
    static const byte psk[32] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    int port = (argc > 1) ? atoi(argv[1]) : 4433;
    const char* identity = (argc > 2) ? argv[2] : "Client_identity";
    struct sockaddr_in sa;
    WC_RNG rng;
    wn_Session sess;
    byte scratch[8192];
    byte in[512];
    word32 got = 0;
    int lfd, cfd, rc, one = 1;

    signal(SIGPIPE, SIG_IGN);
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        printf("socket failed\n");
        return 1;
    }
    (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((unsigned short)port);
    if ((bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) != 0) ||
        (listen(lfd, 1) != 0)) {
        printf("bind/listen on port %d failed\n", port);
        close(lfd);
        return 1;
    }

    cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        printf("accept failed\n");
        close(lfd);
        return 1;
    }

    if (wc_InitRng(&rng) != 0) {
        printf("rng init failed\n");
        close(cfd);
        close(lfd);
        return 1;
    }

    rc = wn_Accept_Psk_ex(&sess, &rng, sock_send, sock_recv, &cfd, psk,
                          (word32)sizeof(psk), identity, scratch,
                          sizeof(scratch));
    if (rc != 0) {
        printf("handshake failed: %d\n", rc);
        wc_FreeRng(&rng);
        close(cfd);
        close(lfd);
        return 1;
    }
    printf("TLS 1.3 handshake complete\n");

    rc = wn_Recv(&sess, in, sizeof(in), &got);
    if (rc == 0) {
        static const char reply[] = "I hear you fa shizzle!";
        printf("received %u bytes: %.*s\n", (unsigned)got, (int)got, in);
        rc = wn_Send(&sess, (const byte*)reply, (word32)(sizeof(reply) - 1));
    }
    if (rc != 0) {
        printf("application data failed: %d\n", rc);
    }

    wn_Close(&sess);
    wc_FreeRng(&rng);
    close(cfd);
    close(lfd);

    return (rc == 0) ? 0 : 1;
}
