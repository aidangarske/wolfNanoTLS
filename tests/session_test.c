/* session_test.c
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
 * Offline unit tests for the application-data session (wn_Send / wn_Recv /
 * wn_Close, src/wn_session.c). A mock transport feeds crafted, peer-encrypted
 * records into wn_Recv and captures wn_Send output for decryption, so the whole
 * record-layer + post-handshake dispatch (app-data, NewSessionTicket skip,
 * KeyUpdate rekey, close_notify, buffer bounds) is exercised without a network.
 */

#include "wn_session.h"
#include "wn_record.h"
#include "wn_keyschedule.h"
#include <wolfssl/wolfcrypt/hash.h>
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

typedef struct {
    byte rx[4096];
    word32 rxLen;
    word32 rxPos;
    byte tx[4096];
    word32 txLen;
} mock_io;

static int m_send(void* ctx, const byte* buf, word32 len)
{
    mock_io* m = (mock_io*)ctx;
    XMEMCPY(m->tx + m->txLen, buf, len);
    m->txLen += len;
    return (int)len;
}

static int m_recv(void* ctx, byte* buf, word32 len)
{
    mock_io* m = (mock_io*)ctx;
    word32 n = m->rxLen - m->rxPos;
    if (n > len) {
        n = len;
    }
    XMEMCPY(buf, m->rx + m->rxPos, n);
    m->rxPos += n;
    return (int)n;
}

/* Append one peer-encrypted record (key/iv/seq, content type ct) to rx. */
static void push_rec(mock_io* m, const byte* key, const byte* iv, word32 seq,
                     byte ct, const byte* data, word32 len)
{
    word32 rl = 0;
    wn_Record_Protect(m->rx + m->rxLen, &rl, key, WN_AEAD_KEY_SZ, iv, seq, ct,
                      data, len);
    m->rxLen += rl;
}

static byte scratch[4096];
static const byte cSec[32] = {
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66
};
static const byte sSec[32] = {
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55
};

/* Reset a session + mock to a fresh established state with deterministic keys
 * derived from the test secrets, mirroring what the handshake produces. */
static void setup(wn_Session* s, mock_io* m)
{
    XMEMSET(m, 0, sizeof(*m));
    XMEMSET(s, 0, sizeof(*s));
    s->ioSend = m_send;
    s->ioRecv = m_recv;
    s->ioCtx = m;
    s->scratch = scratch;
    s->scratchLen = sizeof(scratch);
    s->digest = WC_SHA256;
    s->flags = WN_SESS_ESTABLISHED;
    XMEMCPY(s->cAppSecret, cSec, 32);
    XMEMCPY(s->sAppSecret, sSec, 32);
    wn_Tls13_ExpandLabel(s->cKey, WN_AEAD_KEY_SZ, cSec, "key", NULL, 0,
                         WC_SHA256);
    wn_Tls13_ExpandLabel(s->cIv, WN_AEAD_IV_SZ, cSec, "iv", NULL, 0, WC_SHA256);
    wn_Tls13_ExpandLabel(s->sKey, WN_AEAD_KEY_SZ, sSec, "key", NULL, 0,
                         WC_SHA256);
    wn_Tls13_ExpandLabel(s->sIv, WN_AEAD_IV_SZ, sSec, "iv", NULL, 0, WC_SHA256);
}

int main(void)
{
    wn_Session s;
    mock_io m;
    byte out[512];
    byte sKey2[16], sIv2[12], sSec2[32];
    byte ku[5];
    byte alert[2];
    byte big[600];
    byte plain[512];
    byte ct;
    word32 got, pl;
    int rc;

    /* 1. wn_Send frames an application_data record decryptable with cKey. */
    setup(&s, &m);
    rc = wn_Send(&s, (const byte*)"hello", 5);
    pl = 0;
    ct = 0;
    if (rc == 0) {
        rc = wn_Record_Unprotect(plain, &pl, &ct, s.cKey, WN_AEAD_KEY_SZ,
                                 s.cIv, 0, m.tx, m.txLen);
    }
    check((rc == 0) && (pl == 5) && (ct == WN_REC_APPDATA) &&
          (XMEMCMP(plain, "hello", 5) == 0), "wn_Send emits app-data record");
    check(s.cSeq == 1, "wn_Send increments write sequence");

    /* 2. wn_Recv returns an application_data record. */
    setup(&s, &m);
    push_rec(&m, s.sKey, s.sIv, 0, WN_REC_APPDATA, (const byte*)"world", 5);
    got = 0;
    rc = wn_Recv(&s, out, sizeof(out), &got);
    check((rc == 0) && (got == 5) && (XMEMCMP(out, "world", 5) == 0),
          "wn_Recv returns app data");

    /* 3. wn_Recv skips a NewSessionTicket and returns the following app data. */
    setup(&s, &m);
    {
        byte nst[8];
        nst[0] = 4;                 /* NewSessionTicket */
        nst[1] = 0; nst[2] = 0; nst[3] = 4;
        nst[4] = 0; nst[5] = 0; nst[6] = 0; nst[7] = 0;
        push_rec(&m, s.sKey, s.sIv, 0, WN_REC_HANDSHAKE, nst, sizeof(nst));
    }
    push_rec(&m, s.sKey, s.sIv, 1, WN_REC_APPDATA, (const byte*)"abc", 3);
    got = 0;
    rc = wn_Recv(&s, out, sizeof(out), &got);
    check((rc == 0) && (got == 3) && (XMEMCMP(out, "abc", 3) == 0),
          "wn_Recv skips NewSessionTicket");

    /* 4. wn_Recv processes KeyUpdate (not requested): rekey peer, then read
     *    app data encrypted with the updated key at sequence 0. */
    setup(&s, &m);
    ku[0] = 24;                     /* KeyUpdate */
    ku[1] = 0; ku[2] = 0; ku[3] = 1;
    ku[4] = 0;                      /* update_not_requested */
    push_rec(&m, s.sKey, s.sIv, 0, WN_REC_HANDSHAKE, ku, sizeof(ku));
    XMEMCPY(sSec2, sSec, 32);
    wn_Tls13_KeyUpdate(sSec2, sKey2, sIv2, WC_SHA256);
    push_rec(&m, sKey2, sIv2, 0, WN_REC_APPDATA, (const byte*)"rekeyed", 7);
    got = 0;
    rc = wn_Recv(&s, out, sizeof(out), &got);
    check((rc == 0) && (got == 7) && (XMEMCMP(out, "rekeyed", 7) == 0),
          "wn_Recv processes KeyUpdate then reads app data");

    /* 5. KeyUpdate (update_requested): wn_Recv must send our KeyUpdate. */
    setup(&s, &m);
    ku[4] = 1;                      /* update_requested */
    push_rec(&m, s.sKey, s.sIv, 0, WN_REC_HANDSHAKE, ku, sizeof(ku));
    XMEMCPY(sSec2, sSec, 32);
    wn_Tls13_KeyUpdate(sSec2, sKey2, sIv2, WC_SHA256);
    push_rec(&m, sKey2, sIv2, 0, WN_REC_APPDATA, (const byte*)"x", 1);
    got = 0;
    rc = wn_Recv(&s, out, sizeof(out), &got);
    check((rc == 0) && (got == 1) && (m.txLen > 0),
          "wn_Recv answers update_requested with a KeyUpdate");
    check(s.cSeq == 0, "our write sequence reset after sending KeyUpdate");

    /* 6. close_notify alert -> WOLFNANOTLS_E_CLOSED, no data. */
    setup(&s, &m);
    alert[0] = 1;                   /* warning */
    alert[1] = 0;                   /* close_notify */
    push_rec(&m, s.sKey, s.sIv, 0, WN_REC_ALERT, alert, sizeof(alert));
    got = 99;
    rc = wn_Recv(&s, out, sizeof(out), &got);
    check((rc == WOLFNANOTLS_E_CLOSED) && (got == 0), "wn_Recv reports close_notify");

    /* 7. output buffer too small is rejected, not overflowed. */
    setup(&s, &m);
    XMEMSET(big, 0x41, sizeof(big));
    push_rec(&m, s.sKey, s.sIv, 0, WN_REC_APPDATA, big, sizeof(big));
    got = 0;
    rc = wn_Recv(&s, out, 16, &got);
    check((rc != 0) && (got == 0), "wn_Recv rejects undersized output buffer");

    /* 8. wn_Close emits an encrypted close_notify and wipes the session. */
    setup(&s, &m);
    rc = wn_Close(&s);
    pl = 0;
    ct = 0;
    if (m.txLen > 0) {
        wn_Tls13_ExpandLabel(s.cKey, WN_AEAD_KEY_SZ, cSec, "key", NULL, 0,
                             WC_SHA256);
        wn_Tls13_ExpandLabel(s.cIv, WN_AEAD_IV_SZ, cSec, "iv", NULL, 0,
                             WC_SHA256);
        (void)wn_Record_Unprotect(plain, &pl, &ct, s.cKey, WN_AEAD_KEY_SZ,
                                  s.cIv, 0, m.tx, m.txLen);
    }
    check((rc == 0) && (ct == WN_REC_ALERT) && (pl == 2) && (plain[1] == 0),
          "wn_Close sends close_notify");

    /* session key material is zeroed after close */
    setup(&s, &m);
    wn_Close(&s);
    check((s.cSeq == 0) && (s.flags == 0) && (s.scratch == NULL),
          "wn_Close wipes the session");

    if (fails == 0) {
        printf("session_test: all checks passed\n");
    }
    else {
        printf("session_test: %d FAILED\n", fails);
    }

    return fails == 0 ? 0 : 1;
}
