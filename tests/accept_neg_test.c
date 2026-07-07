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
#include "wn_handshake.h"
#include "wn_keyshare.h"
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

/* PSK of examples/client.c, whose captured ClientHello has a valid binder. */
static const byte g_ex_psk[32] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};
/* captured valid TLS 1.3 PSK ClientHello record (219 B) + client CCS (6 B) */
static const byte g_valid_psk_ch[225] = {
    0x16,0x03,0x03,0x00,0xd6,0x01,0x00,0x00,0xd2,0x03,0x03,0x24,
    0x0e,0xf8,0xca,0xb0,0xcf,0x55,0x4a,0x8e,0x74,0x6e,0x24,0x50,
    0x0a,0x8c,0x97,0x3a,0x5c,0x48,0xc7,0x38,0x77,0xd1,0x10,0xa8,
    0x89,0xce,0x4d,0x9e,0xa0,0x20,0x49,0x20,0x83,0x5e,0xc3,0x21,
    0xd6,0x2f,0xe9,0x62,0x2f,0xab,0x3b,0xb8,0x64,0x0e,0xd0,0x8b,
    0x5d,0x19,0x9b,0x91,0xd4,0x74,0xa5,0x6f,0x46,0x17,0x51,0xaa,
    0xe8,0x86,0x6f,0x36,0x00,0x02,0x13,0x01,0x01,0x00,0x00,0x87,
    0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x00,0x0a,0x00,0x04,0x00,
    0x02,0x00,0x1d,0x00,0x0d,0x00,0x06,0x00,0x04,0x08,0x07,0x04,
    0x03,0x00,0x33,0x00,0x26,0x00,0x24,0x00,0x1d,0x00,0x20,0x82,
    0xdd,0x58,0x00,0x14,0x18,0x73,0x15,0xe9,0xd1,0x13,0x69,0x5f,
    0x99,0xd5,0x8a,0xec,0x01,0x61,0x9c,0xb5,0xd2,0x45,0xa0,0xb5,
    0xda,0x5d,0xe0,0x25,0xb6,0xd9,0x03,0x00,0x2d,0x00,0x02,0x01,
    0x01,0x00,0x29,0x00,0x3a,0x00,0x15,0x00,0x0f,0x43,0x6c,0x69,
    0x65,0x6e,0x74,0x5f,0x69,0x64,0x65,0x6e,0x74,0x69,0x74,0x79,
    0x00,0x00,0x00,0x00,0x00,0x21,0x20,0xb5,0xe3,0x21,0x54,0xc1,
    0xf3,0xe0,0xd5,0xb5,0x01,0xb0,0x82,0x78,0x25,0xde,0xe7,0x21,
    0x6b,0x65,0xe4,0x74,0x61,0x07,0xfb,0x4e,0x32,0x04,0x82,0x84,
    0x11,0x2e,0xe4,0x14,0x03,0x03,0x00,0x01,0x01,
};

static int accept_psk_ch(const byte* rec, word32 len, const byte* psk,
                         word32 pskLen, const char* id)
{
    mock_io m;
    WC_RNG rng;
    byte scr[4096];
    int rc;

    XMEMSET(&m, 0, sizeof(m));
    m.in = rec;
    m.inLen = len;
    wc_InitRng(&rng);
    rc = wn_Accept_Psk(&rng, m_send, m_recv, &m, psk, pskLen, id, scr,
                       sizeof(scr));
    wc_FreeRng(&rng);
    return rc;
}

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
    wn_Session sc, ss;
    wn_KeyShare ks;
    mock_io mr;
    byte spub[128], ssec[64];
    word32 splen, seclen;
    byte scratch[4096];
    byte rec[512];
    byte body[256];
    byte hs32[32], eh[32], z32[32], th32[32];
    word32 rl, mlen;
    int rc, k;

    wc_InitRng(&rng);

    /* ----- wn_RecvHandshake reassembles a message split across two records ----- */
    rec[0] = 22; rec[1] = 3; rec[2] = 3; rec[3] = 0; rec[4] = 6;   /* record 1 */
    rec[5] = 1; rec[6] = 0; rec[7] = 0; rec[8] = 8;                /* hs: type 1, len 8 */
    rec[9] = 0xAA; rec[10] = 0xAA;                                 /* payload[0..2] */
    rec[11] = 22; rec[12] = 3; rec[13] = 3; rec[14] = 0; rec[15] = 6; /* record 2 */
    for (k = 0; k < 6; k++) {
        rec[16 + k] = 0xAA;                                       /* payload[2..8] */
    }
    XMEMSET(&mr, 0, sizeof(mr));
    mr.in = rec;
    mr.inLen = 22;
    mlen = 0;
    rc = wn_RecvHandshake(m_recv, &mr, body, sizeof(body), scratch,
                          sizeof(scratch), &mlen);
    check((rc == WOLFNANO_SUCCESS) && (mlen == 12) && (body[0] == 1),
          "handshake message reassembled across two records");

    /* ----- wn_SessionEstablish: client and server key polarity are inverse ----- */
    for (k = 0; k < 32; k++) {
        hs32[k] = (byte)k; eh[k] = (byte)(k + 1); z32[k] = 0;
        th32[k] = (byte)(k + 2);
    }
    XMEMSET(&sc, 0, sizeof(sc));
    XMEMSET(&ss, 0, sizeof(ss));
    (void)wn_SessionEstablish(WN_ROLE_CLIENT, &sc, hs32, eh, z32, th32, m_send,
                              m_recv, NULL, scratch, sizeof(scratch));
    (void)wn_SessionEstablish(WN_ROLE_SERVER, &ss, hs32, eh, z32, th32, m_send,
                              m_recv, NULL, scratch, sizeof(scratch));
    check((memcmp(sc.cKey, ss.sKey, 16) == 0) &&
          (memcmp(sc.sKey, ss.cKey, 16) == 0),
          "session-establish client/server key polarity is inverse");

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

    /* ----- full NULL / zero-input validation on the _ex entry points ----- */
    XMEMSET(&mr, 0, sizeof(mr));
    check(wn_Accept_Psk_ex(&sc, &rng, NULL, m_recv, &mr, g_psk, sizeof(g_psk),
              g_id, scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "PSK_ex NULL ioSend");
    check(wn_Accept_Psk_ex(&sc, &rng, m_send, NULL, &mr, g_psk, sizeof(g_psk),
              g_id, scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "PSK_ex NULL ioRecv");
    check(wn_Accept_Psk_ex(&sc, &rng, m_send, m_recv, &mr, NULL, sizeof(g_psk),
              g_id, scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "PSK_ex NULL psk");
    check(wn_Accept_Psk_ex(&sc, &rng, m_send, m_recv, &mr, g_psk, 0, g_id,
              scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "PSK_ex zero pskLen");
    check(wn_Accept_Psk_ex(&sc, &rng, m_send, m_recv, &mr, g_psk, sizeof(g_psk),
              NULL, scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "PSK_ex NULL identity");
    check(wn_Accept_Psk_ex(&sc, &rng, m_send, m_recv, &mr, g_psk, sizeof(g_psk),
              g_id, NULL, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "PSK_ex NULL scratch");
    check(wn_Accept_Cert_ex(&sc, &rng, NULL, m_recv, &mr, rec, 8, rec, 8, 0x0403,
              scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "cert_ex NULL ioSend");
    check(wn_Accept_Cert_ex(&sc, &rng, m_send, m_recv, &mr, NULL, 8, rec, 8,
              0x0403, scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "cert_ex NULL certDer");
    check(wn_Accept_Cert_ex(&sc, &rng, m_send, m_recv, &mr, rec, 8, NULL, 8,
              0x0403, scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "cert_ex NULL keyDer");

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

    /* ----- PSK identity + binder rejection over a captured valid CH ----- */
    check(accept_psk_ch(g_valid_psk_ch, sizeof(g_valid_psk_ch), g_ex_psk,
                        sizeof(g_ex_psk), "WrongIdentity")
              == WOLFNANO_E_ILLEGAL_PARAM, "PSK wrong identity rejected");
    XMEMCPY(body, g_valid_psk_ch, sizeof(g_valid_psk_ch));
    body[218] ^= 0x01;                     /* corrupt the last PSK binder byte */
    check(accept_psk_ch(body, sizeof(g_valid_psk_ch), g_ex_psk, sizeof(g_ex_psk),
                        "Client_identity") == WOLFNANO_E_BAD_MAC,
          "PSK corrupted binder rejected (BAD_MAC)");

    /* ----- cert server rejects a signature scheme the client did not offer ----- */
    XMEMSET(&mr, 0, sizeof(mr));
    mr.in = g_valid_psk_ch;
    mr.inLen = sizeof(g_valid_psk_ch);
    check(wn_Accept_Cert_ex(&sc, &rng, m_send, m_recv, &mr, rec, 8, rec, 8,
                            0xFFFF, scratch, sizeof(scratch))
              == WOLFNANO_E_ILLEGAL_PARAM, "cert server rejects unoffered scheme");

    /* ----- legacy_session_id length > 32 must be rejected before any copy ----- */
    XMEMSET(body, 0, sizeof(body));
    body[0] = 1;                             /* ClientHello */
    body[4] = 0x03; body[5] = 0x03;          /* legacy_version (random follows) */
    body[38] = 64;                           /* legacy_session_id length = 64 (>32) */
    body[1] = 0; body[2] = 0; body[3] = 99;  /* handshake length = 4+2+32+1+64-4 */
    rl = wrap_record(rec, body, 103);
    check(run_psk(rec, rl, 0, 0) != WOLFNANO_SUCCESS,
          "oversize legacy_session_id rejected (no stack overflow)");

    /* ----- wn_KeyShare_ServerShare argument + malformed-peer rejection ----- */
    rc = wn_KeyShare_Init(&ks, WN_DEFAULT_GROUP);
    check(rc == WOLFNANO_SUCCESS, "keyshare init");
    check(wn_KeyShare_ServerShare(&ks, &rng, NULL, 0, spub, &splen, ssec,
                                  &seclen) == WOLFNANO_E_INVALID_ARG,
          "ServerShare NULL peer share rejected");
    check(wn_KeyShare_ServerShare(&ks, &rng, (const byte*)spub, 3, spub, &splen,
                                  ssec, &seclen) != WOLFNANO_SUCCESS,
          "ServerShare short peer share rejected");
    (void)wn_KeyShare_Free(&ks);

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
