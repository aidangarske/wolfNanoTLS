/* floor_test.c
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

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
    }
}

static int eq(const byte* a, const byte* b, word32 n)
{
    return XMEMCMP(a, b, n) == 0;
}

/* SHA-256("abc") KAT (FIPS 180-4) */
static void test_sha256(void)
{
    static const byte exp[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    byte out[32];
    int rc = wc_Sha256Hash((const byte*)"abc", 3, out);
    check(rc == 0 && eq(out, exp, 32), "SHA-256 KAT (abc)");
}

/* HKDF-SHA256 RFC 5869 test case 1 */
static void test_hkdf(void)
{
    byte ikm[22], salt[13], info[10], okm[42];
    static const byte exp[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
    };
    int i, rc;
    XMEMSET(ikm, 0x0b, sizeof(ikm));
    for (i = 0; i < (int)sizeof(salt); i++) {
        salt[i] = (byte)i;
    }
    for (i = 0; i < (int)sizeof(info); i++) {
        info[i] = (byte)(0xf0 + i);
    }
    rc = wc_HKDF(WC_SHA256, ikm, sizeof(ikm), salt, sizeof(salt),
                 info, sizeof(info), okm, sizeof(okm));
    check(rc == 0 && eq(okm, exp, sizeof(exp)), "HKDF-SHA256 RFC5869 #1");
}

/* AES-128-GCM KAT: key/IV all-zero, PT=16 zero bytes (NIST) */
static void test_aesgcm(void)
{
    static const byte key[16] = {0};
    static const byte iv[12]  = {0};
    static const byte pt[16]  = {0};
    static const byte ct_exp[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
    };
    static const byte tag_exp[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    Aes aes;
    byte ct[16], tag[16], dec[16];
    int rc, ok;
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    rc |= wc_AesGcmSetKey(&aes, key, sizeof(key));
    rc |= wc_AesGcmEncrypt(&aes, ct, pt, sizeof(pt), iv, sizeof(iv),
                           tag, sizeof(tag), NULL, 0);
    ok = (rc == 0) && eq(ct, ct_exp, 16) && eq(tag, tag_exp, 16);
    rc = wc_AesGcmDecrypt(&aes, dec, ct, sizeof(ct), iv, sizeof(iv),
                          tag, sizeof(tag), NULL, 0);
    ok = ok && (rc == 0) && eq(dec, pt, 16);
    wc_AesFree(&aes);
    check(ok, "AES-128-GCM KAT + round-trip");
}

static void test_x25519(WC_RNG* rng)
{
    curve25519_key a, b;
    byte sa[CURVE25519_KEYSIZE], sb[CURVE25519_KEYSIZE];
    word32 la = sizeof(sa), lb = sizeof(sb);
    int rc, ok;
    wc_curve25519_init(&a);
    wc_curve25519_init(&b);
    rc  = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, &a);
    rc |= wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, &b);
    rc |= wc_curve25519_shared_secret(&a, &b, sa, &la);
    rc |= wc_curve25519_shared_secret(&b, &a, sb, &lb);
    ok = (rc == 0) && (la == lb) && eq(sa, sb, la);
    wc_curve25519_free(&a);
    wc_curve25519_free(&b);
    check(ok, "X25519 ECDH agreement");
}

static void test_ecc(WC_RNG* rng, int keySize, const char* name)
{
    ecc_key key;
    byte hash[32], sig[140];
    word32 sigLen = sizeof(sig);
    int rc, verify = 0, ok;
    XMEMSET(hash, 0x5a, sizeof(hash));
    rc  = wc_ecc_init(&key);
    rc |= wc_ecc_make_key(rng, keySize, &key);
    rc |= wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, &key);
    rc |= wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &verify, &key);
    ok = (rc == 0) && (verify == 1);
    wc_ecc_free(&key);
    check(ok, name);
}

static void test_ed25519(WC_RNG* rng)
{
    ed25519_key key;
    byte sig[ED25519_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    const byte msg[5] = { 'h','e','l','l','o' };
    int rc, verify = 0, ok;
    rc  = wc_ed25519_init(&key);
    rc |= wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key);
    rc |= wc_ed25519_sign_msg(msg, sizeof(msg), sig, &sigLen, &key);
    rc |= wc_ed25519_verify_msg(sig, sigLen, msg, sizeof(msg), &verify, &key);
    ok = (rc == 0) && (verify == 1);
    wc_ed25519_free(&key);
    check(ok, "Ed25519 sign/verify");
}

int main(void)
{
    WC_RNG rng;
    int rc;

    printf("wolfNano crypto floor self-test\n");
    rc = wc_InitRng(&rng);
    check(rc == 0, "Hash-DRBG init");

    test_sha256();
    test_hkdf();
    test_aesgcm();
    test_x25519(&rng);
    test_ecc(&rng, 32, "ECDSA P-256 sign/verify");
    test_ecc(&rng, 48, "ECDSA P-384 sign/verify");
    test_ed25519(&rng);

    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
