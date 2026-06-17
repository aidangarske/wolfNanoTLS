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

int main(int argc, char** argv)
{
    static const byte psk[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    struct sockaddr_in sa;
    WC_RNG rng;
    byte scratch[8192];
    int fd, port, rc;

    port = (argc > 1) ? atoi(argv[1]) : 4433;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket failed\n");
        return 2;
    }
    XMEMSET(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        printf("connect failed\n");
        return 2;
    }

    if (wc_InitRng(&rng) != 0) {
        printf("rng failed\n");
        return 2;
    }

    rc = wn_Connect_Psk(&rng, sock_send, sock_recv, &fd, psk, sizeof(psk),
                        "Client_identity", scratch, sizeof(scratch));

    wc_FreeRng(&rng);
    close(fd);

    printf("wn_Connect_Psk = %d\n", rc);
    printf("%s\n", (rc == 0) ? "PASS TLS 1.3 PSK handshake vs OpenSSL"
                             : "FAIL handshake");
    return (rc == 0) ? 0 : 1;
}
