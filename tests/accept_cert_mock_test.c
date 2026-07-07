/* accept_cert_mock_test.c
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
 * The wolfNanoTLS TLS 1.3 certificate server (wn_Accept_Cert_ex) completing a
 * full handshake against the real wolfNanoTLS cert client (wn_Connect_Cert_ex)
 * run in a forked process over a socketpair, then an application-data round
 * trip. Usage: accept_cert_mock_test <cert.der> <key.der> <scheme-hex>.
 */

#include "wn_accept.h"
#include "wn_connect.h"
#include "wn_servercert.h"
#include "wolfnano_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

typedef struct {
    int fd;
} io_ctx;

static int sock_send(void* ctx, const byte* buf, word32 len)
{
    return (int)send(((io_ctx*)ctx)->fd, buf, len, 0);
}

static int sock_recv(void* ctx, byte* buf, word32 len)
{
    return (int)recv(((io_ctx*)ctx)->fd, buf, len, 0);
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

static byte g_cert[4096];
static byte g_key[4096];
static word32 g_certLen, g_keyLen;

/* Forked client: cert connect (anchor == self-signed leaf), ping, expect pong. */
static void run_client(int fd)
{
    wn_Session sess;
    WC_RNG rng;
    io_ctx ioc;
    byte scratch[16384];
    byte buf[64];
    word32 got = 0;

    int crc;
    ioc.fd = fd;
    wc_InitRng(&rng);
    crc = wn_Connect_Cert_ex(&sess, &rng, sock_send, sock_recv, &ioc, g_cert,
                             g_certLen, scratch, sizeof(scratch));
    if (crc != WOLFNANO_SUCCESS) {
        fprintf(stderr, "  [client wn_Connect_Cert_ex rc=%d]\n", crc);
    }
    if (crc == WOLFNANO_SUCCESS) {
        if (wn_Send(&sess, (const byte*)"ping", 4) == WOLFNANO_SUCCESS) {
            (void)wn_Recv(&sess, buf, sizeof(buf), &got);
        }
        (void)wn_Close(&sess);
    }
    wc_FreeRng(&rng);
}

int main(int argc, char** argv)
{
    wn_Session sess;
    WC_RNG rng;
    io_ctx ioc;
    byte scratch[16384];
    byte buf[64];
    word32 got = 0;
    word16 scheme;
    int sv[2];
    pid_t pid;
    int status, rc;

    if (argc < 4) {
        printf("usage: %s <cert.der> <key.der> <scheme-hex>\n", argv[0]);
        return 1;
    }
    g_certLen = load(argv[1], g_cert, sizeof(g_cert));
    g_keyLen = load(argv[2], g_key, sizeof(g_key));
    scheme = (word16)strtol(argv[3], NULL, 16);
    if ((g_certLen == 0) || (g_keyLen == 0)) {
        printf("could not load cert/key\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("socketpair failed\n");
        return 1;
    }
    pid = fork();
    if (pid == 0) {
        close(sv[0]);
        run_client(sv[1]);
        close(sv[1]);
        _exit(0);
    }
    close(sv[1]);

    ioc.fd = sv[0];
    wc_InitRng(&rng);
    rc = wn_Accept_Cert_ex(&sess, &rng, sock_send, sock_recv, &ioc, g_cert,
                           g_certLen, g_key, g_keyLen, scheme, scratch,
                           sizeof(scratch));
    if (rc != WOLFNANO_SUCCESS) {
        fprintf(stderr, "  [server wn_Accept_Cert_ex rc=%d certLen=%u keyLen=%u scheme=0x%04x]\n",
                rc, (unsigned)g_certLen, (unsigned)g_keyLen, scheme);
    }
    check(rc == WOLFNANO_SUCCESS, "cert server handshake completes vs real client");
    if (rc == WOLFNANO_SUCCESS) {
        rc = wn_Recv(&sess, buf, sizeof(buf), &got);
        check((rc == WOLFNANO_SUCCESS) && (got == 4) &&
              (memcmp(buf, "ping", 4) == 0), "server receives client app data");
        check(wn_Send(&sess, (const byte*)"pong", 4) == WOLFNANO_SUCCESS,
              "server sends app data");
        (void)wn_Close(&sess);
    }
    wc_FreeRng(&rng);
    close(sv[0]);
    waitpid(pid, &status, 0);

    if (fails == 0) {
        printf("accept_cert_mock_test: all checks passed\n");
    }
    else {
        printf("accept_cert_mock_test: %d FAILED\n", fails);
    }
    return fails == 0 ? 0 : 1;
}
