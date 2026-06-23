/* client_cert.c
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
 * Minimal wolfNano TLS 1.3 client: ECDHE handshake with X.509 server-cert
 * authentication, then one application-data round trip and a clean close.
 * The server leaf must verify against the pinned trust anchor (DER). Shows
 * the cert lifecycle: wn_Connect_CertName_ex -> wn_Send -> wn_Recv -> wn_Close.
 *
 * Usage: client_cert <host> <port> <anchor.der>
 *        (default 127.0.0.1 4433 tests/pki/server/ec-cert.der)
 * Try it against:  openssl s_server -tls1_3 -accept 4433 \
 *                    -cert tests/pki/server/ec-cert.pem \
 *                    -key tests/pki/server/ec-key.pem -rev
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
    static const byte msg[] = "hello from wolfNano\n";
    const char* host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 4433;
    const char* anchorPath =
        (argc > 3) ? argv[3] : "tests/pki/server/ec-cert.der";
    struct sockaddr_in sa;
    WC_RNG rng;
    wn_Session sess;
    byte anchor[4096];
    byte scratch[12288];
    byte in[512];
    FILE* f;
    size_t anchorLen;
    word32 got = 0;
    int fd, rc;

    f = fopen(anchorPath, "rb");
    if (f == NULL) {
        printf("cannot open anchor %s\n", anchorPath);
        return 1;
    }
    anchorLen = fread(anchor, 1, sizeof(anchor), f);
    fclose(f);
    if (anchorLen == 0) {
        printf("empty anchor %s\n", anchorPath);
        return 1;
    }

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

    /* Bind the server identity to <host>: the leaf must chain to the anchor and
     * present <host> in its SAN/CN. Pass an SPKI pin instead of host (or both)
     * to authenticate one fixed server by key. host must match the cert. */
    rc = wn_Connect_CertName_ex(&sess, &rng, sock_send, sock_recv, &fd, anchor,
                                (word32)anchorLen, host, NULL, 0,
                                scratch, sizeof(scratch));
    if (rc != 0) {
        printf("handshake failed: %d\n", rc);
        wc_FreeRng(&rng);
        close(fd);
        return 1;
    }
    printf("TLS 1.3 cert handshake complete\n");

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
