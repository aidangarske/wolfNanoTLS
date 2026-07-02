/* client_cert_min.c
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

#include "wn_connect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

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
    static const byte msg[] = "GET / HTTP/1.0\r\n\r\n";
    const char* host = (argc > 1) ? argv[1] : "127.0.0.1";
    const char* port = (argc > 2) ? argv[2] : "4433";
    const char* anchorPath =
        (argc > 3) ? argv[3] : "tests/pki/server/ec-cert.der";
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* ai;
    WC_RNG rng;
    wn_Session sess;
    byte anchor[4096];
    byte scratch[12288];
    byte in[512];
    FILE* f;
    size_t anchorLen;
    word32 got = 0;
    int fd = -1, rc;

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

    XMEMSET(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        printf("resolve %s failed\n", host);
        return 1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        printf("connect to %s:%s failed\n", host, port);
        return 1;
    }

    if (wc_InitRng(&rng) != 0) {
        printf("rng init failed\n");
        close(fd);
        return 1;
    }

    /* Anchor-only: the leaf must chain to the pinned anchor DER. Pin the anchor
     * to the exact expected server; this tier binds identity by that pin, not
     * by hostname (WOLFNANO_X509_HOSTNAME is compiled out). */
    rc = wn_Connect_Cert_ex(&sess, &rng, sock_send, sock_recv, &fd, anchor,
                            (word32)anchorLen, scratch, sizeof(scratch));
    if (rc != 0) {
        printf("handshake failed: %d\n", rc);
        wc_FreeRng(&rng);
        close(fd);
        return 1;
    }
    printf("TLS 1.3 cert handshake complete (P-256/SHA-256, anchor-pinned)\n");

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
