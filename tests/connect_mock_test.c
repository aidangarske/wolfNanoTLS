/* connect_mock_test.c
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
 * Deterministic offline coverage for the TLS 1.3 client handshake driver
 * (wn_Connect_Psk_ex). A minimal PSK+ECDHE server is run in a forked process
 * over a socketpair and built from wolfNanoTLS's own primitives (key share, key
 * schedule, transcript, record), so the client completes a full handshake with
 * no network and no third-party peer. Error cases inject malformed server
 * responses to drive the client's rejection paths.
 */

#include "wn_connect.h"
#include "wn_keyshare.h"
#include "wn_keyschedule.h"
#include "wn_transcript.h"
#include "wn_record.h"
#include "wn_msg.h"
#include "wolfnano_crypto.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#ifdef WN_ALLOC_WATCH
extern int wn_alloc_watch;
extern unsigned long wn_alloc_count;
#endif

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

static const byte g_psk[16] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};
static const char g_id[] = "Client_identity";

typedef struct {
    int fd;
    int failAt;                                 /* fail the failAt-th send (0=never) */
    int n;
} io_ctx;

static int sock_send(void* ctx, const byte* buf, word32 len)
{
    io_ctx* c = (io_ctx*)ctx;
    c->n++;
    if ((c->failAt != 0) && (c->n == c->failAt)) {
        return -1;                              /* injected transport failure */
    }
    return (int)send(c->fd, buf, len, 0);
}

static int sock_recv(void* ctx, byte* buf, word32 len)
{
    io_ctx* c = (io_ctx*)ctx;
    return (int)recv(c->fd, buf, len, 0);
}

static int read_exact(int fd, byte* buf, word32 n)
{
    word32 got = 0;
    int r;
    while (got < n) {
        r = (int)recv(fd, buf + got, n - got, 0);
        if (r <= 0) {
            return -1;
        }
        got += (word32)r;
    }
    return 0;
}

/* Read one TLS record (header + fragment) into rec; returns total length. */
static int srv_read_rec(int fd, byte* rec, word32 cap, byte* type,
                        word32* recLen)
{
    word32 frag;
    if (read_exact(fd, rec, 5) != 0) {
        return -1;
    }
    *type = rec[0];
    frag = ((word32)rec[3] << 8) | rec[4];
    if (frag > cap - 5) {                       /* bound fragment to caller buffer */
        return -1;
    }
    if (read_exact(fd, rec + 5, frag) != 0) {
        return -1;
    }
    *recLen = frag + 5;
    return 0;
}

static void srv_send_plain(int fd, byte type, const byte* body, word32 len)
{
    byte hdr[5];
    hdr[0] = type; hdr[1] = 0x03; hdr[2] = 0x03;
    hdr[3] = (byte)(len >> 8); hdr[4] = (byte)(len & 0xff);
    (void)send(fd, hdr, 5, 0);
    (void)send(fd, body, len, 0);
}

/* Pull the client's 32-byte X25519 key_share public from a ClientHello body. */
static int parse_client_pub(const byte* ch, word32 chLen, byte* pub)
{
    wn_Reader r;
    word32 extEnd;
    word16 extLen, et, el, csLen, sharesLen, grp, klen;
    byte sidLen, compLen;
    const byte* p;
    int found = 0;

    wn_Reader_Init(&r, ch, chLen);
    (void)wn_Read_U8(&r);                       /* msg type */
    (void)wn_Read_U24(&r);                      /* msg len */
    (void)wn_Read_U16(&r);                      /* legacy_version */
    (void)wn_Read_Bytes(&r, 32);                /* random */
    sidLen = wn_Read_U8(&r);
    (void)wn_Read_Bytes(&r, sidLen);
    csLen = wn_Read_U16(&r);
    (void)wn_Read_Bytes(&r, csLen);
    compLen = wn_Read_U8(&r);
    (void)wn_Read_Bytes(&r, compLen);
    extLen = wn_Read_U16(&r);
    extEnd = r.pos + extLen;
    if (extEnd > chLen) {                       /* bound the loop to the input */
        extEnd = chLen;
    }
    while ((r.pos < extEnd) && (r.err == 0) && (found == 0)) {
        et = wn_Read_U16(&r);
        el = wn_Read_U16(&r);
        if (et == 51) {                         /* key_share */
            sharesLen = wn_Read_U16(&r);
            (void)sharesLen;
            grp = wn_Read_U16(&r);
            klen = wn_Read_U16(&r);
            p = wn_Read_Bytes(&r, klen);
            if ((grp == 0x001d) && (klen == 32) && (p != NULL)) {
                XMEMCPY(pub, p, 32);
                found = 1;
            }
        }
        else {
            (void)wn_Read_Bytes(&r, el);
        }
    }
    return (found && (r.err == 0)) ? 0 : -1;
}

static const byte g_hrr_random[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

/* mode: 0 = valid handshake; 1 = ServerHello not a handshake record;
 * 2 = bad key_share length; 3 = corrupt server Finished MAC;
 * 8 = ServerHello carrying the HelloRetryRequest random sentinel. */
static void run_server(int fd, int mode)
{
    wn_KeyShare ks;
    wn_Transcript tc;
    WC_RNG rng;
    byte rec[4096];
    byte cliPub[32], srvPub[32], ecdhe[32];
    byte random32[32], emptyHash[32], th[32];
    byte early[32], derived[32], hs[32], cHs[32], sHs[32];
    byte sKey[16], sIv[12], mac[32];
    byte sh[256], ee[64], plainFlight[1024], encRec[1100];
    wn_Writer w;
    word32 chLen, recLen, pubLen, ssLen, thLen, encLen, flightLen;
    byte rtype = 0;
    word32 ext, body;

    wc_InitRng(&rng);
    wn_Transcript_Init(&tc, WC_SHA256);
    wc_Sha256Hash((const byte*)"", 0, emptyHash);
    wc_RNG_GenerateBlock(&rng, random32, 32);
    if (mode == 8) {
        XMEMCPY(random32, g_hrr_random, 32);
    }

    /* 1. ClientHello */
    srv_read_rec(fd, rec, sizeof(rec), &rtype, &recLen);
    chLen = recLen - 5;
    parse_client_pub(rec + 5, chLen, cliPub);
    wn_Transcript_Update(&tc, rec + 5, chLen);

    /* 2. server ECDHE */
    wn_KeyShare_Init(&ks, WN_GROUP_X25519);
    wn_KeyShare_Generate(&ks, &rng, srvPub, &pubLen);
    wn_KeyShare_Shared(&ks, cliPub, 32, ecdhe, &ssLen);

    if (mode == 1) {
        /* send the ServerHello as an (illegal) application_data record */
        srv_send_plain(fd, WN_REC_APPDATA, random32, 16);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    /* 3. ServerHello */
    wn_Writer_Init(&w, sh, sizeof(sh));
    wn_Write_U8(&w, 2);                          /* ServerHello */
    body = wn_Write_LenStart(&w, 3);
    wn_Write_U16(&w, 0x0303);
    wn_Write_Bytes(&w, random32, 32);
    wn_Write_U8(&w, 32);                         /* echo client session_id */
    wn_Write_Bytes(&w, rec + 44, 32);
    wn_Write_U16(&w, 0x1301);
    wn_Write_U8(&w, 0);
    ext = wn_Write_LenStart(&w, 2);
    wn_Write_U16(&w, 43); wn_Write_U16(&w, 2); wn_Write_U16(&w, 0x0304);
    wn_Write_U16(&w, 51);                        /* key_share */
    if (mode == 8) {
        /* real HelloRetryRequest: key_share is just the 2-byte selected_group */
        wn_Write_U16(&w, 2);
        wn_Write_U16(&w, 0x001d);
    }
    else {
        wn_Write_U16(&w, (mode == 2) ? 20 : 36);
        wn_Write_U16(&w, 0x001d);
        wn_Write_U16(&w, (mode == 2) ? 16 : 32);
        wn_Write_Bytes(&w, srvPub, (mode == 2) ? 16 : 32);
    }
    wn_Write_U16(&w, 41); wn_Write_U16(&w, 2); wn_Write_U16(&w, 0); /* psk sel 0 */
    wn_Write_LenEnd(&w, ext, 2);
    wn_Write_LenEnd(&w, body, 3);
    srv_send_plain(fd, WN_REC_HANDSHAKE, sh, w.len);
    wn_Transcript_Update(&tc, sh, w.len);

    /* compat ChangeCipherSpec after ServerHello (client skips it) */
    ee[0] = 0x01;
    srv_send_plain(fd, WN_REC_CHANGE_CIPHER, ee, 1);

    if ((mode == 2) || (mode == 8)) {
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    /* 4. handshake key schedule (mirrors the client) */
    wn_Transcript_GetHash(&tc, th, &thLen);
    wn_Tls13_Extract(early, NULL, 0, g_psk, sizeof(g_psk), WC_SHA256);
    wn_Tls13_DeriveSecret(derived, early, "derived", emptyHash, 32, WC_SHA256);
    wn_Tls13_Extract(hs, derived, 32, ecdhe, 32, WC_SHA256);
    wn_Tls13_DeriveSecret(cHs, hs, "c hs traffic", th, 32, WC_SHA256);
    wn_Tls13_DeriveSecret(sHs, hs, "s hs traffic", th, 32, WC_SHA256);
    wn_Tls13_ExpandLabel(sKey, 16, sHs, "key", NULL, 0, WC_SHA256);
    wn_Tls13_ExpandLabel(sIv, 12, sHs, "iv", NULL, 0, WC_SHA256);

    if (mode == 7) {
        /* an unencrypted handshake record where the flight is expected */
        srv_send_plain(fd, WN_REC_HANDSHAKE, ee, 4);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    if (mode == 5) {
        /* malformed handshake message in the flight: claim a huge length */
        plainFlight[0] = 8; plainFlight[1] = 0xff; plainFlight[2] = 0xff;
        plainFlight[3] = 0xff;
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                          plainFlight, 4);
        (void)send(fd, encRec, encLen, 0);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    if (mode == 9) {
        /* inner record larger than the client's plain[512] decrypt buffer */
        byte pad[600];
        XMEMSET(pad, 0, sizeof(pad));
        wn_Writer_Init(&w, plainFlight, sizeof(plainFlight));
        wn_Write_U8(&w, 8);
        ext = wn_Write_LenStart(&w, 3);
        wn_Write_U16(&w, (word16)sizeof(pad));
        wn_Write_Bytes(&w, pad, sizeof(pad));
        wn_Write_LenEnd(&w, ext, 3);
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                          plainFlight, w.len);
        (void)send(fd, encRec, encLen, 0);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    if (mode == 10) {
        /* two EncryptedExtensions in the flight (RFC 8446 allows one) */
        wn_Writer_Init(&w, plainFlight, sizeof(plainFlight));
        wn_Write_U8(&w, 8); wn_Write_U24(&w, 2); wn_Write_U16(&w, 0);
        wn_Write_U8(&w, 8); wn_Write_U24(&w, 2); wn_Write_U16(&w, 0);
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                          plainFlight, w.len);
        (void)send(fd, encRec, encLen, 0);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    if ((mode == 13) || (mode == 14) || (mode == 15)) {
        /* EncryptedExtensions body checks: forbidden ext, missing vector,
         * and an extension length that overruns the vector. */
        wn_Writer_Init(&w, plainFlight, sizeof(plainFlight));
        wn_Write_U8(&w, 8);
        if (mode == 14) {
            wn_Write_U24(&w, 0);            /* no extensions vector field */
        }
        else {
            ext = wn_Write_LenStart(&w, 3);
            wn_Write_U16(&w, 4);            /* extensions vector length */
            wn_Write_U16(&w, (mode == 13) ? 51 : 10);  /* 51 forbidden in EE */
            wn_Write_U16(&w, (mode == 15) ? 0xFFFF : 0);
            wn_Write_LenEnd(&w, ext, 3);
        }
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                          plainFlight, w.len);
        (void)send(fd, encRec, encLen, 0);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    if (mode == 18) {
        /* valid EE then a message whose length cannot fit the reassembly buffer */
        wn_Writer_Init(&w, plainFlight, sizeof(plainFlight));
        wn_Write_U8(&w, 8); wn_Write_U24(&w, 2); wn_Write_U16(&w, 0);
        wn_Write_U8(&w, 20); wn_Write_U24(&w, 0xffffff);
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                          plainFlight, w.len);
        (void)send(fd, encRec, encLen, 0);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    if (mode == 11) {
        /* Finished before any EncryptedExtensions */
        XMEMSET(mac, 0, 32);
        wn_Writer_Init(&w, plainFlight, sizeof(plainFlight));
        wn_Write_U8(&w, 20); wn_Write_U24(&w, 32);
        wn_Write_Bytes(&w, mac, 32);
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                          plainFlight, w.len);
        (void)send(fd, encRec, encLen, 0);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    if (mode == 12) {
        /* encrypted record whose inner type is not handshake, mid-flight */
        XMEMSET(plainFlight, 0, 4);
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_APPDATA,
                          plainFlight, 4);
        (void)send(fd, encRec, encLen, 0);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    /* 5. EncryptedExtensions (empty) [+ extra msg, mode 6] + server Finished */
    wn_Writer_Init(&w, plainFlight, sizeof(plainFlight));
    wn_Write_U8(&w, 8);                          /* EncryptedExtensions */
    ext = wn_Write_LenStart(&w, 3);
    if (mode == 17) {
        wn_Write_U16(&w, 8);                     /* one supported_groups ext */
        wn_Write_U16(&w, 10); wn_Write_U16(&w, 4);
        wn_Write_U16(&w, 2); wn_Write_U16(&w, 0x001d);
    }
    else {
        wn_Write_U16(&w, 0);                     /* extensions length 0 */
    }
    wn_Write_LenEnd(&w, ext, 3);
    if (mode == 6) {
        wn_Write_U8(&w, 99);                     /* unexpected (ignored) message */
        wn_Write_U24(&w, 1);
        wn_Write_U8(&w, 0);
    }
    XMEMCPY(ee, plainFlight, w.len);            /* EE(+extra) for the transcript */
    wn_Transcript_Update(&tc, ee, w.len);
    wn_Transcript_GetHash(&tc, th, &thLen);     /* hash through EE(+extra) */
    wn_Tls13_FinishedMac(mac, sHs, th, 32, WC_SHA256);
    if (mode == 3) {
        mac[0] ^= 0xff;                          /* corrupt the Finished MAC */
    }
    wn_Write_U8(&w, 20);                         /* Finished */
    wn_Write_U24(&w, 32);
    wn_Write_Bytes(&w, mac, 32);
    flightLen = w.len;

    if (mode == 16) {
        /* split the flight mid-Finished across two records (RFC 8446 5.1) */
        word32 cut = flightLen - 16;
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                          plainFlight, cut);
        (void)send(fd, encRec, encLen, 0);
        encLen = 0;
        wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 1, WN_REC_HANDSHAKE,
                          plainFlight + cut, flightLen - cut);
        (void)send(fd, encRec, encLen, 0);
        (void)srv_read_rec(fd, rec, sizeof(rec), &rtype, &recLen);
        (void)srv_read_rec(fd, rec, sizeof(rec), &rtype, &recLen);
        wn_KeyShare_Free(&ks); wc_FreeRng(&rng); return;
    }

    encLen = 0;
    wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                      plainFlight, flightLen);
    (void)send(fd, encRec, encLen, 0);

    /* 6. drain the client's leftover CCS then its Finished, so the socket stays
     * open until the client has sent its Finished (avoids a close race). */
    (void)srv_read_rec(fd, rec, sizeof(rec), &rtype, &recLen);
    (void)srv_read_rec(fd, rec, sizeof(rec), &rtype, &recLen);

    wn_KeyShare_Free(&ks);
    wc_FreeRng(&rng);
}

static int g_failSessClean = 1;

/* Run one handshake against a forked mock server. failAt injects a transport
 * failure on the failAt-th client send (0 = never); wrapper uses the
 * handshake-only wn_Connect_Psk instead of the _ex form. */
static int drive_ex(int mode, int failAt, int wrapper)
{
    int sv[2];
    pid_t pid;
    wn_Session sess;
    WC_RNG rng;
    io_ctx ioc;
    byte scratch[8192];
    int rc, status;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return -100;
    }
    pid = fork();
    if (pid == 0) {
        close(sv[0]);
        run_server(sv[1], mode);
        close(sv[1]);
        _exit(0);
    }
    close(sv[1]);

    ioc.fd = sv[0]; ioc.failAt = failAt; ioc.n = 0;
    wc_InitRng(&rng);
#ifdef WN_ALLOC_WATCH
    wn_alloc_watch = 1;              /* count allocations across the handshake */
#endif
    if (wrapper) {
        rc = wn_Connect_Psk(&rng, sock_send, sock_recv, &ioc, g_psk,
                            sizeof(g_psk), g_id, scratch, sizeof(scratch));
    }
    else {
        XMEMSET(&sess, 0xAA, sizeof(sess));
        rc = wn_Connect_Psk_ex(&sess, &rng, sock_send, sock_recv, &ioc, g_psk,
                               sizeof(g_psk), g_id, scratch, sizeof(scratch));
        if ((rc != WOLFNANO_SUCCESS) && (sess.flags != 0)) {
            g_failSessClean = 0;        /* failure left a non-clean session */
        }
    }
#ifdef WN_ALLOC_WATCH
    wn_alloc_watch = 0;
#endif
    wc_FreeRng(&rng);
    close(sv[0]);
    waitpid(pid, &status, 0);
    return rc;
}

static int drive(int mode)
{
    return drive_ex(mode, 0, 0);
}

#ifndef WN_ALLOC_WATCH
static char g_bigid[0x10001];                   /* 65536 chars > 0xFFFF identity */
#endif

int main(void)
{
#ifdef WN_ALLOC_WATCH
    int rc;

    signal(SIGPIPE, SIG_IGN);
    rc = drive(0);
    check(rc == WOLFNANO_SUCCESS, "PSK handshake completes (alloc trap)");
    check(wn_alloc_count == 0, "zero heap allocations during full PSK handshake");
    if (fails == 0) {
        printf("connect_mock_test: all checks passed (alloc trap)\n");
    }
    else {
        printf("connect_mock_test: %d FAILED\n", fails);
    }
    return fails == 0 ? 0 : 1;
#else
    byte scratch[8];
    byte bscratch[2048];
    wn_Session bsess;
    WC_RNG rng;

    signal(SIGPIPE, SIG_IGN);                   /* writes to a closed peer -> EPIPE */
    check(drive(0) == WOLFNANO_SUCCESS, "PSK handshake completes vs mock server");

    wc_InitRng(&rng);
    XMEMSET(g_bigid, 'a', sizeof(g_bigid) - 1);
    g_bigid[sizeof(g_bigid) - 1] = '\0';
    check(wn_Connect_Psk_ex(&bsess, &rng, sock_send, sock_recv, NULL, g_psk,
          sizeof(g_psk), g_bigid, bscratch, sizeof(bscratch))
          == WOLFNANO_E_INVALID_ARG, "over-long PSK identity rejected");
    wc_FreeRng(&rng);
    check(drive_ex(0, 0, 1) == WOLFNANO_SUCCESS, "handshake via wn_Connect_Psk wrapper");
    check(drive(1) != WOLFNANO_SUCCESS, "ServerHello not a handshake record rejected");
    check(drive(2) != WOLFNANO_SUCCESS, "bad server key_share length rejected");
    check(drive(3) == WOLFNANO_E_BAD_MAC, "corrupt server Finished -> BAD_MAC");
    check(drive(5) == WOLFNANO_E_DECODE, "malformed flight message -> DECODE");
    check(drive(6) == WOLFNANO_E_UNEXPECTED_MSG,
          "unexpected flight message rejected (PSK grammar)");
    check(drive(7) == WOLFNANO_E_UNEXPECTED_MSG, "non-appdata record in flight rejected");
    check(drive(8) == WOLFNANO_E_UNSUPPORTED, "HelloRetryRequest detected and rejected");
    check(drive(9) == WOLFNANO_E_DECODE, "oversized server flight record rejected");
    check(drive(10) == WOLFNANO_E_UNEXPECTED_MSG,
          "duplicate EncryptedExtensions rejected");
    check(drive(11) == WOLFNANO_E_BAD_MAC,
          "Finished before EncryptedExtensions rejected");
    check(drive(12) == WOLFNANO_E_UNEXPECTED_MSG,
          "non-handshake inner record in flight rejected");
    check(drive(13) == WOLFNANO_E_UNEXPECTED_MSG,
          "forbidden EncryptedExtensions extension rejected");
    check(drive(14) == WOLFNANO_E_DECODE,
          "EncryptedExtensions with no extensions vector rejected");
    check(drive(15) == WOLFNANO_E_DECODE,
          "EncryptedExtensions extension length overrun rejected");
    check(drive(16) == WOLFNANO_SUCCESS,
          "fragmented server flight reassembled across records");
    check(drive(17) == WOLFNANO_SUCCESS,
          "EncryptedExtensions with supported_groups accepted");
    check(drive(18) == WOLFNANO_E_DECODE,
          "reassembly rejects a message larger than the buffer after a prior one");

    /* transport send failures: ClientHello header, ClientHello body, Finished */
    check(drive_ex(0, 1, 0) != WOLFNANO_SUCCESS, "ClientHello header send failure");
    check(drive_ex(0, 2, 0) != WOLFNANO_SUCCESS, "ClientHello body send failure");
    check(drive_ex(0, 5, 0) != WOLFNANO_SUCCESS, "client Finished send failure");
    check(g_failSessClean, "failed handshake leaves a clean (zeroed) session");

    /* argument validation */
    wc_InitRng(&rng);
    check(wn_Connect_Psk_ex(NULL, &rng, sock_send, sock_recv, NULL, g_psk,
          sizeof(g_psk), g_id, scratch, sizeof(scratch)) == WOLFNANO_E_INVALID_ARG,
          "NULL session / tiny scratch rejected");
    wc_FreeRng(&rng);

    if (fails == 0) {
        printf("connect_mock_test: all checks passed\n");
    }
    else {
        printf("connect_mock_test: %d FAILED\n", fails);
    }
    return fails == 0 ? 0 : 1;
#endif
}
