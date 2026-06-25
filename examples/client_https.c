/* client_https.c
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
 * Live wolfNano TLS 1.3 client against a real HTTPS endpoint: resolve the host,
 * connect, do an ECDHE handshake with SNI + X.509 chain/hostname verification
 * against a trust anchor (root CA, DER), then send an HTTP/1.1 GET and print the
 * status line. Demonstrates wn_Connect_CertName_ex end-to-end on the internet.
 *
 * Usage: client_https <host> <anchor.der> [port]   (default port 443)
 * e.g.:  client_https valid-isrgrootx1.letsencrypt.org isrgrootx1.der
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
    const char* host = (argc > 1) ? argv[1] : "valid-isrgrootx1.letsencrypt.org";
    const char* anchorPath = (argc > 2) ? argv[2] : "isrgrootx1.der";
    const char* port = (argc > 3) ? argv[3] : "443";
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    WC_RNG rng;
    wn_Session sess;
    byte anchor[4096];
    byte scratch[20480];
    byte req[512];
    byte in[16385];     /* a full 2^14 record plaintext + room for a NUL */
    struct addrinfo* ai;
    FILE* f;
    size_t anchorLen;
    int reqLen;
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

    /* SNI is sent automatically because host is non-NULL; the leaf must chain to
     * the anchor (root CA) and present host in its SAN/CN. */
    rc = wn_Connect_CertName_ex(&sess, &rng, sock_send, sock_recv, &fd, anchor,
                                (word32)anchorLen, host, NULL, 0,
                                scratch, sizeof(scratch));
    if (rc != 0) {
        printf("handshake to %s failed: %d\n", host, rc);
        wc_FreeRng(&rng);
        close(fd);
        return 1;
    }
    printf("TLS 1.3 handshake to %s OK (SNI + cert verified)\n", host);

    reqLen = snprintf((char*)req, sizeof(req),
                      "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: wolfNano\r\n"
                      "Connection: close\r\n\r\n", host);
    if ((reqLen < 0) || (reqLen >= (int)sizeof(req))) {
        printf("request too long for %s\n", host);
        wn_Close(&sess);
        wc_FreeRng(&rng);
        close(fd);
        return 1;
    }
    rc = wn_Send(&sess, req, (word32)reqLen);
    if (rc == 0) {
        rc = wn_Recv(&sess, in, sizeof(in) - 1, &got);
    }
    if ((rc == 0) && (got > 0)) {
        in[got] = 0;
        printf("server replied %u bytes, status: %.*s\n", (unsigned)got,
               (int)strcspn((char*)in, "\r\n"), (char*)in);
        rc = ((got >= 7) && (XMEMCMP(in, "HTTP/1.", 7) == 0)) ? 0 : 1;
    }
    else {
        printf("application data failed: %d\n", rc);
        rc = 1;
    }

    wn_Close(&sess);
    wc_FreeRng(&rng);
    close(fd);

    return rc;
}
