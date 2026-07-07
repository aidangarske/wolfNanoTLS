/* accept_mock_test.c
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
 * The wolfNanoTLS TLS 1.3 PSK + ECDHE server (wn_Accept_Psk_ex) completing a
 * full handshake against the real wolfNanoTLS client (wn_Connect_Psk_ex) run in
 * a forked process over a socketpair, then an application-data round trip.
 */

#include "wn_accept.h"
#include "wn_connect.h"
#include "wolfnano_crypto.h"
#include <stdio.h>
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

static const byte g_psk[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
static const char g_id[] = "Client_identity";

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

/* Forked client: connect, send "ping", expect "pong", close. */
static void run_client(int fd)
{
    wn_Session sess;
    WC_RNG rng;
    io_ctx ioc;
    byte scratch[8192];
    byte buf[64];
    word32 got = 0;

    ioc.fd = fd;
    wc_InitRng(&rng);
    if (wn_Connect_Psk_ex(&sess, &rng, sock_send, sock_recv, &ioc, g_psk,
                          sizeof(g_psk), g_id, scratch, sizeof(scratch))
            == WOLFNANO_SUCCESS) {
        if (wn_Send(&sess, (const byte*)"ping", 4) == WOLFNANO_SUCCESS) {
            (void)wn_Recv(&sess, buf, sizeof(buf), &got);
        }
        (void)wn_Close(&sess);
    }
    wc_FreeRng(&rng);
}

int main(void)
{
    wn_Session sess;
    WC_RNG rng;
    io_ctx ioc;
    byte scratch[8192];
    byte buf[64];
    word32 got = 0;
    int sv[2];
    pid_t pid;
    int status;
    int rc;

    signal(SIGPIPE, SIG_IGN);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("accept_mock_test: socketpair failed\n");
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
    rc = wn_Accept_Psk_ex(&sess, &rng, sock_send, sock_recv, &ioc, g_psk,
                          sizeof(g_psk), g_id, scratch, sizeof(scratch));
    check(rc == WOLFNANO_SUCCESS, "PSK server handshake completes vs real client");
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
        printf("accept_mock_test: all checks passed\n");
    }
    else {
        printf("accept_mock_test: %d FAILED\n", fails);
    }
    return fails == 0 ? 0 : 1;
}
