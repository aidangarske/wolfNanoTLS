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
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
    }
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
    word32 recLen = 0, outLen = 0;
    byte type = 0;
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

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
