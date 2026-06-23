/* connect_mock_hybrid_test.c
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
 * Offline functional coverage for the X25519MLKEM768 hybrid handshake. A forked
 * mock server (built from wolfNanoTLS's own wn_Hybrid_* KEM) completes a full
 * TLS 1.3 PSK + hybrid handshake with wn_Connect_Psk_ex over a socketpair, so
 * the hybrid keyshare + connect integration is exercised end-to-end, no network.
 */

#include "wn_connect.h"
#include "wn_keyshare.h"
#include "wn_keyschedule.h"
#include "wn_transcript.h"
#include "wn_record.h"
#include "wn_hybrid.h"
#include "wn_msg.h"
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

static const byte g_psk[16] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};
static const char g_id[] = "Client_identity";

typedef struct { int fd; } io_ctx;

static int sock_send(void* ctx, const byte* buf, word32 len)
{
    return (int)send(((io_ctx*)ctx)->fd, buf, len, 0);
}

static int sock_recv(void* ctx, byte* buf, word32 len)
{
    return (int)recv(((io_ctx*)ctx)->fd, buf, len, 0);
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

/* Pull the client's hybrid key_share (group 0x11ec) from the ClientHello. */
static int parse_client_share(const byte* ch, word32 chLen, byte* share)
{
    wn_Reader r;
    word32 extEnd;
    word16 extLen, et, el, csLen, grp, klen;
    byte sidLen, compLen;
    const byte* p;
    int found = 0;

    wn_Reader_Init(&r, ch, chLen);
    (void)wn_Read_U8(&r);
    (void)wn_Read_U24(&r);
    (void)wn_Read_U16(&r);
    (void)wn_Read_Bytes(&r, 32);
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
        if (et == 51) {
            (void)wn_Read_U16(&r);              /* shares length */
            grp = wn_Read_U16(&r);
            klen = wn_Read_U16(&r);
            p = wn_Read_Bytes(&r, klen);
            if ((grp == WN_GROUP_X25519MLKEM768) &&
                (klen == WN_HYBRID_CLIENT_SHARE) && (p != NULL)) {
                XMEMCPY(share, p, WN_HYBRID_CLIENT_SHARE);
                found = 1;
            }
        }
        else {
            (void)wn_Read_Bytes(&r, el);
        }
    }
    return (found && (r.err == 0)) ? 0 : -1;
}

static void run_server(int fd)
{
    wn_Transcript tc;
    WC_RNG rng;
    byte rec[4096];
    byte cliShare[WN_HYBRID_CLIENT_SHARE];
    byte srvShare[WN_HYBRID_SERVER_SHARE];
    byte ecdhe[WN_HYBRID_SECRET];
    byte random32[32], emptyHash[32], th[32];
    byte early[32], derived[32], hs[32], cHs[32], sHs[32];
    byte sKey[16], sIv[12], mac[32];
    byte sh[1400], ee[64], plainFlight[256], encRec[512];
    wn_Writer w;
    word32 chLen, recLen, ssLen, srvLen, thLen, encLen, flightLen;
    byte rtype = 0;
    word32 ext, body;

    wc_InitRng(&rng);
    wn_Transcript_Init(&tc, WC_SHA256);
    wc_Sha256Hash((const byte*)"", 0, emptyHash);
    wc_RNG_GenerateBlock(&rng, random32, 32);

    srv_read_rec(fd, rec, sizeof(rec), &rtype, &recLen);
    chLen = recLen - 5;
    parse_client_share(rec + 5, chLen, cliShare);
    wn_Transcript_Update(&tc, rec + 5, chLen);

    srvLen = 0;
    ssLen = 0;
    wn_Hybrid_ServerRespond(cliShare, WN_HYBRID_CLIENT_SHARE, &rng,
                            srvShare, &srvLen, ecdhe, &ssLen);

    wn_Writer_Init(&w, sh, sizeof(sh));
    wn_Write_U8(&w, 2);
    body = wn_Write_LenStart(&w, 3);
    wn_Write_U16(&w, 0x0303);
    wn_Write_Bytes(&w, random32, 32);
    wn_Write_U8(&w, 0);
    wn_Write_U16(&w, 0x1301);
    wn_Write_U8(&w, 0);
    ext = wn_Write_LenStart(&w, 2);
    wn_Write_U16(&w, 43); wn_Write_U16(&w, 2); wn_Write_U16(&w, 0x0304);
    wn_Write_U16(&w, 51);                            /* key_share */
    wn_Write_U16(&w, (word16)(4 + WN_HYBRID_SERVER_SHARE));
    wn_Write_U16(&w, WN_GROUP_X25519MLKEM768);
    wn_Write_U16(&w, WN_HYBRID_SERVER_SHARE);
    wn_Write_Bytes(&w, srvShare, WN_HYBRID_SERVER_SHARE);
    wn_Write_U16(&w, 41); wn_Write_U16(&w, 2); wn_Write_U16(&w, 0); /* psk sel 0 */
    wn_Write_LenEnd(&w, ext, 2);
    wn_Write_LenEnd(&w, body, 3);
    srv_send_plain(fd, WN_REC_HANDSHAKE, sh, w.len);
    wn_Transcript_Update(&tc, sh, w.len);

    ee[0] = 0x01;
    srv_send_plain(fd, WN_REC_CHANGE_CIPHER, ee, 1);

    wn_Transcript_GetHash(&tc, th, &thLen);
    wn_Tls13_Extract(early, NULL, 0, g_psk, sizeof(g_psk), WC_SHA256);
    wn_Tls13_DeriveSecret(derived, early, "derived", emptyHash, 32, WC_SHA256);
    wn_Tls13_Extract(hs, derived, 32, ecdhe, WN_HYBRID_SECRET, WC_SHA256);
    wn_Tls13_DeriveSecret(cHs, hs, "c hs traffic", th, 32, WC_SHA256);
    wn_Tls13_DeriveSecret(sHs, hs, "s hs traffic", th, 32, WC_SHA256);
    wn_Tls13_ExpandLabel(sKey, 16, sHs, "key", NULL, 0, WC_SHA256);
    wn_Tls13_ExpandLabel(sIv, 12, sHs, "iv", NULL, 0, WC_SHA256);

    wn_Writer_Init(&w, plainFlight, sizeof(plainFlight));
    wn_Write_U8(&w, 8);                              /* EncryptedExtensions */
    ext = wn_Write_LenStart(&w, 3);
    wn_Write_U16(&w, 0);
    wn_Write_LenEnd(&w, ext, 3);
    XMEMCPY(ee, plainFlight, w.len);
    wn_Transcript_Update(&tc, ee, w.len);
    wn_Transcript_GetHash(&tc, th, &thLen);
    wn_Tls13_FinishedMac(mac, sHs, th, 32, WC_SHA256);
    wn_Write_U8(&w, 20);                             /* Finished */
    wn_Write_U24(&w, 32);
    wn_Write_Bytes(&w, mac, 32);
    flightLen = w.len;

    encLen = 0;
    wn_Record_Protect(encRec, &encLen, sKey, 16, sIv, 0, WN_REC_HANDSHAKE,
                      plainFlight, flightLen);
    (void)send(fd, encRec, encLen, 0);

    (void)srv_read_rec(fd, rec, sizeof(rec), &rtype, &recLen);
    (void)srv_read_rec(fd, rec, sizeof(rec), &rtype, &recLen);

    wc_FreeRng(&rng);
}

static int drive(void)
{
    int sv[2];
    pid_t pid;
    int rc, status;
    WC_RNG rng;
    wn_Session sess;
    io_ctx ioc;
    byte scratch[8192];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return -1;
    }
    pid = fork();
    if (pid == 0) {
        close(sv[0]);
        run_server(sv[1]);
        close(sv[1]);
        _exit(0);
    }
    close(sv[1]);
    wc_InitRng(&rng);
    ioc.fd = sv[0];
    rc = wn_Connect_Psk_ex(&sess, &rng, sock_send, sock_recv, &ioc, g_psk,
                           sizeof(g_psk), g_id, scratch, sizeof(scratch));
    wc_FreeRng(&rng);
    close(sv[0]);
    waitpid(pid, &status, 0);
    return rc;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    check(drive() == WOLFNANOTLS_SUCCESS, "PSK + X25519MLKEM768 handshake completes");
    if (fails == 0) {
        printf("connect_mock_hybrid_test: all checks passed\n");
    }
    return fails ? 1 : 0;
}
