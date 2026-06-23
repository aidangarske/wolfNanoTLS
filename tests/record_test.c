/* record_test.c
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

/* TLS 1.3 record-protection tests: seal/open round-trip, tamper detection,
 * sequence-number binding. */

#include "wn_record.h"
#include "wolfnano_crypto.h"
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
    const byte* buf;
    word32 len;
    word32 pos;
} buf_io;

static int buf_recv(void* ctx, byte* out, word32 len)
{
    buf_io* b = (buf_io*)ctx;
    word32 n = b->len - b->pos;
    if (n > len) {
        n = len;
    }
    XMEMCPY(out, b->buf + b->pos, n);
    b->pos += n;
    return (int)n;
}

static int zero_recv(void* ctx, byte* out, word32 len)
{
    (void)ctx;
    (void)out;
    (void)len;
    return 0;                                   /* simulate closed connection */
}

int main(void)
{
    static const byte key[16] = {
        0x3f,0xce,0x51,0x60,0x09,0xc2,0x17,0x27,0xd0,0xf2,0xe4,0xe8,0x6e,0xe4,0x03,0xbc
    };
    static const byte iv[12] = {
        0x5d,0x31,0x3e,0xb2,0x67,0x12,0x76,0xee,0x13,0x00,0x0b,0x30
    };
    const byte content[14] = { 'h','e','l','l','o',' ','w','o','l','f','N','a','n','o' };
    byte rec[5 + sizeof(content) + 1 + 16];
    byte out[sizeof(content) + 1];
    byte big2[5 + 4 + 1 + 16];
    byte zc[4];
    byte hdr[5];
    buf_io b;
    word32 recLen = 0, outLen = 0, rl = 0;
    byte type = 0, rtype = 0;
    int rc;

    printf("wolfNano TLS 1.3 record-protection tests\n");

    rc = wn_Record_Protect(rec, &recLen, key, sizeof(key), iv, 0, 22,
                           content, sizeof(content));
    check((rc == WOLFNANO_SUCCESS) &&
          (recLen == (word32)(5 + sizeof(content) + 1 + 16)) &&
          (rec[0] == 23) && (rec[1] == 0x03) && (rec[2] == 0x03),
          "Protect builds a TLSCiphertext record");

    rc = wn_Record_Unprotect(out, &outLen, &type, key, sizeof(key), iv, 0,
                             rec, recLen);
    check((rc == WOLFNANO_SUCCESS) && (outLen == sizeof(content)) &&
          (type == 22) && (XMEMCMP(out, content, sizeof(content)) == 0),
          "Unprotect recovers content and type");

    /* tampering the ciphertext must fail the AEAD tag */
    rec[7] ^= 0x01;
    rc = wn_Record_Unprotect(out, &outLen, &type, key, sizeof(key), iv, 0,
                             rec, recLen);
    check(rc != WOLFNANO_SUCCESS, "tampered record is rejected");
    rec[7] ^= 0x01;

    /* wrong sequence number changes the nonce and must fail */
    rc = wn_Record_Unprotect(out, &outLen, &type, key, sizeof(key), iv, 1,
                             rec, recLen);
    check(rc != WOLFNANO_SUCCESS, "wrong sequence number is rejected");

    /* 64-bit sequence: a value above 2^32 round-trips (upper nonce bytes used) */
    rc = wn_Record_Protect(rec, &recLen, key, sizeof(key), iv,
                           (word64)0x0000000123456789ULL, 22,
                           content, sizeof(content));
    if (rc == WOLFNANO_SUCCESS) {
        rc = wn_Record_Unprotect(out, &outLen, &type, key, sizeof(key), iv,
                                 (word64)0x0000000123456789ULL, rec, recLen);
    }
    check((rc == WOLFNANO_SUCCESS) && (outLen == sizeof(content)),
          "64-bit sequence number round-trips");
    rc = wn_Record_Unprotect(out, &outLen, &type, key, sizeof(key), iv,
                             (word64)0x0000000023456789ULL, rec, recLen);
    check(rc != WOLFNANO_SUCCESS, "differing high sequence word is rejected");

    /* --- negative / edge paths --- */
    check(wn_Record_Protect(NULL, &recLen, key, sizeof(key), iv, 0, 22,
          content, sizeof(content)) == WOLFNANO_E_INVALID_ARG,
          "Protect NULL rejected");
    check(wn_Record_Protect(rec, &recLen, key, 7, iv, 0, 22, content,
          sizeof(content)) != WOLFNANO_SUCCESS, "Protect bad keyLen fails");
    check(wn_Record_Protect(rec, &recLen, key, sizeof(key), iv, 0, 22, content,
          WN_MAX_PLAINTEXT + 1) == WOLFNANO_E_INVALID_ARG,
          "Protect rejects content over the record limit");
    check(wn_Record_Unprotect(NULL, &outLen, &type, key, sizeof(key), iv, 0,
          rec, recLen) == WOLFNANO_E_INVALID_ARG, "Unprotect NULL rejected");
    check(wn_Record_Unprotect(out, &outLen, &type, key, sizeof(key), iv, 0,
          rec, 10) == WOLFNANO_E_INVALID_ARG, "Unprotect short record");
    check(wn_Record_Unprotect(out, &outLen, &type, key, 7, iv, 0, rec, recLen)
          != WOLFNANO_SUCCESS, "Unprotect bad keyLen fails");

    /* all-padding (content + type byte all zero) -> no content type */
    XMEMSET(zc, 0, sizeof(zc));
    rl = 0;
    wn_Record_Protect(big2, &rl, key, sizeof(key), iv, 0, 0, zc, sizeof(zc));
    check(wn_Record_Unprotect(out, &outLen, &type, key, sizeof(key), iv, 0,
          big2, rl) == WOLFNANO_E_DECODE, "all-padding record -> DECODE");

    /* wn_RecvRecord: zero-length fragment, oversized fragment, EOF */
    hdr[0] = 22; hdr[1] = 0x03; hdr[2] = 0x03; hdr[3] = 0; hdr[4] = 0;
    b.buf = hdr; b.len = 5; b.pos = 0;
    check(wn_RecvRecord(buf_recv, &b, rec, sizeof(rec), &rtype, &rl) != 0,
          "RecvRecord zero fragment rejected");
    hdr[3] = 0xff; hdr[4] = 0xff;
    b.buf = hdr; b.len = 5; b.pos = 0;
    check(wn_RecvRecord(buf_recv, &b, rec, sizeof(rec), &rtype, &rl) != 0,
          "RecvRecord oversized fragment rejected");
    check(wn_RecvRecord(zero_recv, &b, rec, sizeof(rec), &rtype, &rl) != 0,
          "RecvRecord EOF rejected");

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
