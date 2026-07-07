/* server_cert.c
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
 * Minimal wolfNanoTLS TLS 1.3 certificate server: presents a leaf cert and signs
 * CertificateVerify, then echoes one record. Lifecycle: accept ->
 * wn_Accept_Cert_ex -> wn_Recv -> wn_Send -> wn_Close.
 *
 * Usage: server_cert <port> <cert.der> <key.der> <scheme-hex>
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

static word32 load(const char* path, byte* buf, word32 cap)
{
    FILE* f = fopen(path, "rb");
    size_t n;

    if (f == NULL) {
        return 0;
    }
    n = fread(buf, 1, cap, f);
    fclose(f);
    return (word32)n;
}

int main(int argc, char** argv)
{
    static const char reply[] = "I hear you fa shizzle!";
    byte cert[8192], key[8192], scratch[24576], in[512];
    struct sockaddr_in sa;
    WC_RNG rng;
    wn_Session sess;
    word32 certLen, keyLen, got = 0;
    word16 scheme;
    int port, lfd, cfd, rc, one = 1;

    if (argc < 5) {
        printf("usage: %s <port> <cert.der> <key.der> <scheme-hex>\n", argv[0]);
        return 1;
    }
    port = atoi(argv[1]);
    certLen = load(argv[2], cert, sizeof(cert));
    keyLen = load(argv[3], key, sizeof(key));
    scheme = (word16)strtol(argv[4], NULL, 16);
    if ((certLen == 0) || (keyLen == 0)) {
        printf("could not load cert/key\n");
        return 1;
    }

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

    rc = wn_Accept_Cert_ex(&sess, &rng, sock_send, sock_recv, &cfd, cert,
                           certLen, key, keyLen, scheme, scratch,
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
