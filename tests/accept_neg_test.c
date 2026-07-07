/* accept_neg_test.c
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
 * Adversarial coverage for the wolfNanoTLS TLS 1.3 server (wn_Accept_Psk /
 * wn_Accept_Cert): argument checks, malformed ClientHello rejection, and I/O
 * failure injection at each handshake step, driven by a scriptable mock I/O.
 */

#include "wn_accept.h"
#include "wn_servercert.h"
#include "wolfnano_crypto.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

/* Mock I/O: recv replays a fixed script; send counts down failAt to fail once. */
typedef struct {
    const byte* in;
    word32 inLen;
    word32 inPos;
    int sendCalls;
    int sendFailAt;    /* fail the Nth send (1-based); 0 = never */
    int recvFailAt;    /* fail the Nth recv (1-based); 0 = never */
    int recvCalls;
} mock_io;

static int m_send(void* ctx, const byte* buf, word32 len)
{
    mock_io* m = (mock_io*)ctx;
    (void)buf;
    m->sendCalls++;
    if (m->sendFailAt != 0 && m->sendCalls == m->sendFailAt) {
        return -1;
    }
    return (int)len;
}

static int m_recv(void* ctx, byte* buf, word32 len)
{
    mock_io* m = (mock_io*)ctx;
    word32 n;

    m->recvCalls++;
    if (m->recvFailAt != 0 && m->recvCalls == m->recvFailAt) {
        return -1;
    }
    n = m->inLen - m->inPos;
    if (n > len) {
        n = len;
    }
    if (n == 0) {
        return -1;
    }
    XMEMCPY(buf, m->in + m->inPos, n);
    m->inPos += n;
    return (int)n;
}

static const byte g_psk[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
static const char g_id[] = "Client_identity";

/* Wrap a handshake body in a TLS record header (type 22 handshake). */
static word32 wrap_record(byte* out, const byte* body, word32 bodyLen)
{
    out[0] = 22;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (byte)(bodyLen >> 8);
    out[4] = (byte)(bodyLen & 0xff);
    XMEMCPY(out + 5, body, bodyLen);
    return bodyLen + 5;
}

static int run_psk(const byte* rec, word32 recLen, int sendFailAt, int recvFailAt)
{
    mock_io m;
    WC_RNG rng;
    byte scratch[4096];
    int rc;

    XMEMSET(&m, 0, sizeof(m));
    m.in = rec;
    m.inLen = recLen;
    m.sendFailAt = sendFailAt;
    m.recvFailAt = recvFailAt;
    wc_InitRng(&rng);
    rc = wn_Accept_Psk(&rng, m_send, m_recv, &m, g_psk, sizeof(g_psk), g_id,
                       scratch, sizeof(scratch));
    wc_FreeRng(&rng);
    return rc;
}

int main(void)
{
    WC_RNG rng;
    byte scratch[4096];
    byte rec[512];
    byte body[256];
    word32 rl;
    int rc;

    wc_InitRng(&rng);

    /* ----- argument validation ----- */
    rc = wn_Accept_Psk(NULL, m_send, m_recv, NULL, g_psk, sizeof(g_psk), g_id,
                       scratch, sizeof(scratch));
    check(rc == WOLFNANO_E_INVALID_ARG, "PSK NULL rng rejected");
    rc = wn_Accept_Psk(&rng, m_send, m_recv, NULL, g_psk, sizeof(g_psk), g_id,
                       scratch, 100);
    check(rc == WOLFNANO_E_INVALID_ARG, "PSK tiny scratch rejected");
    rc = wn_Accept_Cert_ex(NULL, &rng, m_send, m_recv, NULL, rec, 1, rec, 1,
                           0x0403, scratch, sizeof(scratch));
    check(rc == WOLFNANO_E_INVALID_ARG, "Cert NULL sess rejected");
    rc = wn_Accept_Cert_ex((wn_Session*)scratch, &rng, m_send, m_recv, NULL, rec,
                           1, rec, 1, 0x0403, scratch, 100);
    check(rc == WOLFNANO_E_INVALID_ARG, "Cert tiny scratch rejected");

    /* ----- first record not a handshake (alert type 21) ----- */
    body[0] = 0;
    rl = wrap_record(rec, body, 1);
    rec[0] = 21;
    check(run_psk(rec, rl, 0, 0) == WOLFNANO_E_UNEXPECTED_MSG,
          "non-handshake first record rejected");

    /* ----- ClientHello that fails to parse (truncated) ----- */
    body[0] = 1;                 /* ClientHello */
    body[1] = 0; body[2] = 0; body[3] = 40;   /* claims 40 bytes, only a few */
    rl = wrap_record(rec, body, 6);
    check(run_psk(rec, rl, 0, 0) != WOLFNANO_SUCCESS,
          "truncated ClientHello rejected");

    /* ----- recv failure on the first record ----- */
    rl = wrap_record(rec, body, 6);
    check(run_psk(rec, rl, 0, 1) != WOLFNANO_SUCCESS,
          "recv failure on ClientHello rejected");

    /* ----- ServerCert / CertVerify encoder argument checks ----- */
    check(wn_ServerCert_Build(NULL, &rl, sizeof(rec), rec, 1)
          == WOLFNANO_E_INVALID_ARG, "ServerCert_Build NULL out rejected");
    check(wn_ServerCertVerify_Sign(NULL, &rl, sizeof(rec), 0x0403, rec, 1, rec,
          32, &rng) == WOLFNANO_E_INVALID_ARG, "CertVerify_Sign NULL out rejected");
    check(wn_ServerCertVerify_Sign(rec, &rl, sizeof(rec), 0x9999, rec, 1, rec,
          32, &rng) == WOLFNANO_E_UNSUPPORTED, "CertVerify_Sign bad scheme rejected");

    wc_FreeRng(&rng);
    if (fails == 0) {
        printf("accept_neg_test: all checks passed\n");
    }
    else {
        printf("accept_neg_test: %d FAILED\n", fails);
    }
    return fails == 0 ? 0 : 1;
}
