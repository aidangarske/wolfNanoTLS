/* cert_neg_test.c
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

/* Negative authentication coverage for the X.509 cert path: a tampered chain
 * must fail wn_VerifyChain, and a tampered ECDSA CertificateVerify (0x0403)
 * must fail wn_CertVerify. Guards against the auth checks being silently
 * neutralized (mutation survival).
 */

#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>   /* test uses DecodedCert for its own setup */
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#include <wolfssl/certs_test.h>
#include <stdio.h>

#include "../src/wn_connect.c"

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

/* Parse a built ClientHello and report whether the signature_algorithms
 * extension (type 13) offers the given scheme. */
static int sigalg_offered(const byte* ch, word32 chLen, word16 want)
{
    wn_Reader r;
    word32 extEnd, listEnd;
    word16 suitesLen, extTot, et, el, listLen, sch;
    byte sidLen, compLen;
    int found = 0;

    wn_Reader_Init(&r, ch, chLen);
    (void)wn_Read_U8(&r);                /* handshake type */
    (void)wn_Read_U24(&r);               /* handshake length */
    (void)wn_Read_U16(&r);               /* legacy_version */
    (void)wn_Read_Bytes(&r, 32);         /* random */
    sidLen = wn_Read_U8(&r);
    (void)wn_Read_Bytes(&r, sidLen);
    suitesLen = wn_Read_U16(&r);
    (void)wn_Read_Bytes(&r, suitesLen);
    compLen = wn_Read_U8(&r);
    (void)wn_Read_Bytes(&r, compLen);
    extTot = wn_Read_U16(&r);
    extEnd = r.pos + extTot;
    while ((r.pos < extEnd) && (r.err == 0) && (found == 0)) {
        et = wn_Read_U16(&r);
        el = wn_Read_U16(&r);
        if (et == 13) {
            listLen = wn_Read_U16(&r);
            listEnd = r.pos + listLen;
            while ((r.pos + 2 <= listEnd) && (r.err == 0) && (found == 0)) {
                sch = wn_Read_U16(&r);
                if (sch == want) {
                    found = 1;
                }
            }
        }
        else {
            (void)wn_Read_Bytes(&r, el);
        }
    }
    return found;
}

/* EncryptedExtensions bodies (2-byte ext vector len + extensions) */
static const byte ee_empty[]  = { 0x00, 0x00 };
static const byte ee_sgroup[] = { 0x00,0x04, 0x00,0x0a, 0x00,0x00 };
static const byte ee_sni[]    = { 0x00,0x04, 0x00,0x00, 0x00,0x00 };
static const byte ee_sni_ne[] = { 0x00,0x05, 0x00,0x00, 0x00,0x01, 0x00 };
static const byte ee_bad[]    = { 0x00,0x04, 0x00,0x33, 0x00,0x00 };

/* UTC broken-down time -> Unix seconds (no local tz / DST; dates are UTC). */
static long wn_tm_to_unix(const struct tm* t)
{
    static const long md[12] = {0,31,59,90,120,151,181,212,243,273,304,334};
    long y = (long)t->tm_year + 1900;
    long leaps = (y - 1) / 4 - (y - 1) / 100 + (y - 1) / 400 - 477;
    long days = (y - 1970) * 365 + leaps + md[t->tm_mon] + (t->tm_mday - 1);
    if ((t->tm_mon >= 2) &&
        (((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0))) {
        days += 1;
    }
    return ((days * 24 + t->tm_hour) * 60 + t->tm_min) * 60 + t->tm_sec;
}

int main(void)
{
    WC_RNG rng;
    ecc_key ek;
    DecodedCert dcT;
    struct tm tmB, tmA;
    const byte* dB;
    byte fB;
    int lB;
    time_t nowValid = 0, nowPast = 0, nowFuture = 0;
    byte th[32];
    byte tbs[64 + 33 + 1 + 32];
    byte spki[256];
    byte hash[32];
    byte sig[256];
    byte tamper[sizeof(serv_ecc_der_256)];
    byte leafSpki[512];
    const byte* certs[1];
    word32 certLens[1];
    word32 tbsLen = 0;
    word32 sigLen;
    word32 leafSpkiLen;
    byte tmp[512];
    word32 tl;
    int spkiLen, rc, vr, ekInit = 0;
    word32 i;
#if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
    ecc_key ek384;
    byte spki384[256];
    byte hash384[48];
    int ek384Init = 0, sp384Len;
#endif
#ifndef NO_RSA
    RsaKey rsaKey;
    byte rsaSpki[512];
    byte rdg[64];
    byte rsig[512];
    word32 rsaSpkiLen, rsigLen;
    int rsaInit = 0, rsaDerLen;
#endif
#if defined(HAVE_ECC384) && !defined(NO_RSA) && \
    defined(WOLFSSL_SHA384) && defined(WOLFSSL_SHA512)
    byte chbuf[512];
    byte zpub[WN_DEFAULT_PUB_SZ];
    word32 chlen = 0;
#endif
#ifdef WOLFNANO_X509_HOSTNAME
    DecodedCert dc;
    char nameBuf[256];
    const char* nm = NULL;
    int nmLen = 0;
#endif

    printf("wolfNanoTLS X.509 negative auth test (chain + ECDSA CertificateVerify)\n");

    for (i = 0; i < sizeof(th); i++) {
        th[i] = (byte)i;
    }
    wn_BuildCvTbs(tbs, &tbsLen, th, sizeof(th));

    rc = wc_InitRng(&rng);
    check(rc == 0, "RNG init");

    rc = wc_ecc_init(&ek);
    if (rc == 0) {
        ekInit = 1;
        rc = wc_ecc_make_key(&rng, 32, &ek);
    }
    check(rc == 0, "P-256 keygen");

    spkiLen = wc_EccPublicKeyToDer(&ek, spki, (word32)sizeof(spki), 1);
    check(spkiLen > 0, "export public key to SPKI DER");

    rc = wc_Hash(WC_HASH_TYPE_SHA256, tbs, tbsLen, hash, sizeof(hash));
    sigLen = (word32)sizeof(sig);
    if (rc == 0) {
        rc = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, &rng, &ek);
    }
    check(rc == 0, "sign CertificateVerify TBS (ECDSA)");

    vr = wn_CertVerify(0x0403, spki, (word32)spkiLen, th, sizeof(th), sig,
                     sigLen);
    check(vr == WOLFNANO_SUCCESS, "ECDSA CertificateVerify accepted (0x0403)");

    sig[10] ^= 0x01;
    vr = wn_CertVerify(0x0403, spki, (word32)spkiLen, th, sizeof(th), sig,
                     sigLen);
    check(vr != WOLFNANO_SUCCESS, "tampered ECDSA signature rejected");

    /* SPKI algorithm must match the scheme: corrupt id-ecPublicKey so the leaf
     * no longer declares an EC key, restore the valid signature, and confirm
     * 0x0403 is rejected (native binds the SPKI algorithm; asn.c decode fails). */
    sig[10] ^= 0x01;                    /* restore the valid signature */
    check(spki[6] == 0x2A, "SPKI id-ecPublicKey OID at expected offset");
    spki[6] = 0x2B;                     /* 1.2.840... -> unknown OID */
    vr = wn_CertVerify(0x0403, spki, (word32)spkiLen, th, sizeof(th), sig,
                     sigLen);
    check(vr != WOLFNANO_SUCCESS, "CertVerify rejects SPKI algorithm != scheme");
    spki[6] = 0x2A;                     /* restore */

#if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
    rc = wc_ecc_init(&ek384);
    if (rc == 0) {
        ek384Init = 1;
        rc = wc_ecc_make_key(&rng, 48, &ek384);
    }
    check(rc == 0, "P-384 keygen");
    sp384Len = wc_EccPublicKeyToDer(&ek384, spki384, (word32)sizeof(spki384), 1);
    check(sp384Len > 0, "export P-384 SPKI DER");
    rc = wc_Hash(WC_HASH_TYPE_SHA384, tbs, tbsLen, hash384, sizeof(hash384));
    sigLen = (word32)sizeof(sig);
    if (rc == 0) {
        rc = wc_ecc_sign_hash(hash384, sizeof(hash384), sig, &sigLen, &rng,
                              &ek384);
    }
    check(rc == 0, "sign CertificateVerify TBS (ECDSA P-384)");
    vr = wn_CertVerify(0x0503, spki384, (word32)sp384Len, th, sizeof(th), sig,
                       sigLen);
    check(vr == WOLFNANO_SUCCESS, "ECDSA P-384 CertVerify accepted (0x0503)");
    sig[10] ^= 0x01;
    vr = wn_CertVerify(0x0503, spki384, (word32)sp384Len, th, sizeof(th), sig,
                       sigLen);
    check(vr != WOLFNANO_SUCCESS, "tampered ECDSA P-384 signature rejected");
    /* a VALID P-256/SHA-384 signature must still be rejected for the P-384
     * scheme purely on curve binding, not on signature validity. */
    sigLen = (word32)sizeof(sig);
    rc = wc_ecc_sign_hash(hash384, sizeof(hash384), sig, &sigLen, &rng, &ek);
    check(rc == 0, "sign SHA-384 digest with P-256 key");
    vr = wn_CertVerify(0x0503, spki, (word32)spkiLen, th, sizeof(th), sig,
                       sigLen);
    check(vr == WOLFNANO_E_BAD_CERT,
          "P-256 leaf key rejected for P-384 scheme (curve binding)");
#endif

#ifndef NO_RSA
    rc = wc_InitRsaKey(&rsaKey, NULL);
    if (rc == 0) {
        rsaInit = 1;
        rc = wc_MakeRsaKey(&rsaKey, 2048, 65537, &rng);
    }
    check(rc == 0, "RSA-2048 keygen");
    rsaDerLen = wc_RsaKeyToPublicDer(&rsaKey, rsaSpki, (word32)sizeof(rsaSpki));
    check(rsaDerLen > 0, "export RSA SPKI DER");
    rsaSpkiLen = (word32)rsaDerLen;
    #ifdef WOLFSSL_SHA384
    rc = wc_Hash(WC_HASH_TYPE_SHA384, tbs, tbsLen, rdg, 48);
    if (rc == 0) {
        rc = wc_RsaPSS_Sign(rdg, 48, rsig, (word32)sizeof(rsig),
                            WC_HASH_TYPE_SHA384, WC_MGF1SHA384, &rsaKey, &rng);
    }
    check(rc > 0, "sign CertificateVerify TBS (RSA-PSS SHA-384)");
    rsigLen = (word32)rc;
    vr = wn_CertVerify(0x0805, rsaSpki, rsaSpkiLen, th, sizeof(th), rsig,
                       rsigLen);
    check(vr == WOLFNANO_SUCCESS, "RSA-PSS SHA-384 CertVerify accepted (0x0805)");
    rsig[10] ^= 0x01;
    vr = wn_CertVerify(0x0805, rsaSpki, rsaSpkiLen, th, sizeof(th), rsig,
                       rsigLen);
    check(vr != WOLFNANO_SUCCESS, "tampered RSA-PSS SHA-384 rejected");
    #endif
    #ifdef WOLFSSL_SHA512
    rc = wc_Hash(WC_HASH_TYPE_SHA512, tbs, tbsLen, rdg, 64);
    if (rc == 0) {
        rc = wc_RsaPSS_Sign(rdg, 64, rsig, (word32)sizeof(rsig),
                            WC_HASH_TYPE_SHA512, WC_MGF1SHA512, &rsaKey, &rng);
    }
    check(rc > 0, "sign CertificateVerify TBS (RSA-PSS SHA-512)");
    rsigLen = (word32)rc;
    vr = wn_CertVerify(0x0806, rsaSpki, rsaSpkiLen, th, sizeof(th), rsig,
                       rsigLen);
    check(vr == WOLFNANO_SUCCESS, "RSA-PSS SHA-512 CertVerify accepted (0x0806)");
    rsig[10] ^= 0x01;
    vr = wn_CertVerify(0x0806, rsaSpki, rsaSpkiLen, th, sizeof(th), rsig,
                       rsigLen);
    check(vr != WOLFNANO_SUCCESS, "tampered RSA-PSS SHA-512 rejected");
    #endif
#endif

#if defined(HAVE_ECC384) && !defined(NO_RSA) && \
    defined(WOLFSSL_SHA384) && defined(WOLFSSL_SHA512)
    XMEMSET(zpub, 0, sizeof(zpub));
    rc = wn_ClientHello_Build_ex(chbuf, &chlen, sizeof(chbuf), th, NULL, 0,
                                 zpub, sizeof(zpub), NULL);
    check(rc == WOLFNANO_SUCCESS, "build ClientHello for sig-alg wire check");
    check(sigalg_offered(chbuf, chlen, 0x0503),
          "ClientHello offers ecdsa_secp384r1_sha384 (0x0503)");
    check(sigalg_offered(chbuf, chlen, 0x0805),
          "ClientHello offers rsa_pss_rsae_sha384 (0x0805)");
    check(sigalg_offered(chbuf, chlen, 0x0806),
          "ClientHello offers rsa_pss_rsae_sha512 (0x0806)");
    check(!sigalg_offered(chbuf, chlen, 0x0601),
          "ClientHello omits legacy rsa_pkcs1_sha512 (0x0601)");
    check(sigalg_offered(chbuf, chlen, 0x0403),
          "ClientHello offers ecdsa_secp256r1_sha256 (0x0403)");
#endif

    /* derive a clock inside the leaf's own validity so the functional chain
     * checks stay version-agnostic regardless of when the test certs were made. */
    wc_InitDecodedCert(&dcT, serv_ecc_der_256, (word32)sizeof_serv_ecc_der_256,
                       NULL);
    rc = wc_ParseCert(&dcT, CERT_TYPE, NO_VERIFY, NULL);
    if (rc == 0) {
        rc = wc_GetDateInfo(dcT.beforeDate, dcT.beforeDateLen, &dB, &fB, &lB);
    }
    if (rc == 0) {
        rc = wc_GetDateAsCalendarTime(dB, lB, fB, &tmB);
    }
    check(rc == 0, "extract leaf notBefore");
    rc = wc_GetDateInfo(dcT.afterDate, dcT.afterDateLen, &dB, &fB, &lB);
    if (rc == 0) {
        rc = wc_GetDateAsCalendarTime(dB, lB, fB, &tmA);
    }
    check(rc == 0, "extract leaf notAfter");
    wc_FreeDecodedCert(&dcT);
    nowValid  = (time_t)(wn_tm_to_unix(&tmB) + 86400);
    nowPast   = (time_t)(wn_tm_to_unix(&tmB) - 86400);
    nowFuture = (time_t)(wn_tm_to_unix(&tmA) + 86400);

    certs[0] = serv_ecc_der_256;
    certLens[0] = (word32)sizeof_serv_ecc_der_256;
    leafSpkiLen = (word32)sizeof(leafSpki);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, leafSpki,
                        &leafSpkiLen, NULL, NULL, 0, nowValid);
    check(rc == WOLFNANO_SUCCESS, "valid ECC chain verified");

    /* validity-window enforcement (#35): leaf outside [notBefore,notAfter] */
    leafSpkiLen = (word32)sizeof(leafSpki);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, leafSpki,
                        &leafSpkiLen, NULL, NULL, 0, nowPast);
    check(rc == WOLFNANO_E_BAD_CERT, "not-yet-valid cert rejected");
    leafSpkiLen = (word32)sizeof(leafSpki);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, leafSpki,
                        &leafSpkiLen, NULL, NULL, 0, nowFuture);
    check(rc == WOLFNANO_E_BAD_CERT, "expired cert rejected");

    /* key pin: leafSpki now holds the real leaf key; pin against it. */
    tl = (word32)sizeof(tmp);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, tmp, &tl,
                        NULL, leafSpki, leafSpkiLen, nowValid);
    check(rc == WOLFNANO_SUCCESS, "matching public-key pin accepted");
    leafSpki[0] ^= 0x01;
    tl = (word32)sizeof(tmp);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, tmp, &tl,
                        NULL, leafSpki, leafSpkiLen, nowValid);
    check(rc == WOLFNANO_E_BAD_CERT, "wrong key pin rejected");
    leafSpki[0] ^= 0x01;                         /* restore the real pin bytes */
    tl = (word32)sizeof(tmp);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, tmp, &tl,
                        NULL, leafSpki, 0, nowValid);
    check(rc == WOLFNANO_E_BAD_CERT, "zero-length key pin rejected");

#ifdef WOLFNANO_X509_HOSTNAME
    check(wn_DnsNameMatch("example.com", 11, "example.com", 11)
          == WOLFNANO_SUCCESS, "exact host match");
    check(wn_DnsNameMatch("EXAMPLE.com", 11, "example.COM", 11)
          == WOLFNANO_SUCCESS, "case-insensitive host match");
    check(wn_DnsNameMatch("*.example.com", 13, "a.example.com", 13)
          == WOLFNANO_SUCCESS, "wildcard host match");
    check(wn_DnsNameMatch("*.example.com", 13, "a.b.example.com", 15)
          != WOLFNANO_SUCCESS, "wildcard rejects multi-label host");
    check(wn_DnsNameMatch("example.com", 11, "other.com", 9)
          != WOLFNANO_SUCCESS, "host mismatch rejected");

    wc_InitDecodedCert(&dc, serv_ecc_der_256,
                       (word32)sizeof_serv_ecc_der_256, NULL);
    if (wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0) {
        if (dc.altNames != NULL) {
            nm = dc.altNames->name;
            nmLen = dc.altNames->len;
        }
        else {
            nm = dc.subjectCN;
            nmLen = dc.subjectCNLen;
        }
    }
    XMEMCPY(nameBuf, nm, (size_t)nmLen);
    nameBuf[nmLen] = '\0';
    wc_FreeDecodedCert(&dc);

    certs[0] = serv_ecc_der_256;
    certLens[0] = (word32)sizeof_serv_ecc_der_256;
    tl = (word32)sizeof(tmp);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, tmp, &tl,
                        nameBuf, NULL, 0, nowValid);
    check(rc == WOLFNANO_SUCCESS, "leaf hostname accepted");
    tl = (word32)sizeof(tmp);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, tmp, &tl,
                        "no.match.invalid", NULL, 0, nowValid);
    check(rc == WOLFNANO_E_BAD_CERT, "wrong hostname rejected");
#endif /* WOLFNANO_X509_HOSTNAME */

    XMEMCPY(tamper, serv_ecc_der_256, sizeof(serv_ecc_der_256));
    tamper[sizeof(tamper) - 1] ^= 0x01;
    certs[0] = tamper;
    certLens[0] = (word32)sizeof(tamper);
    leafSpkiLen = (word32)sizeof(leafSpki);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, leafSpki,
                        &leafSpkiLen, NULL, NULL, 0, nowValid);
    check(rc == WOLFNANO_E_BAD_CERT, "tampered ECC chain rejected");

    /* EncryptedExtensions acceptance (wn_CheckEncExt): empty, supported_groups,
     * and server_name (allowed only when SNI was offered). */
    check(wn_CheckEncExt(ee_empty, sizeof(ee_empty), 0) == WOLFNANO_SUCCESS,
          "EE empty accepted");
    check(wn_CheckEncExt(ee_sgroup, sizeof(ee_sgroup), 0) == WOLFNANO_SUCCESS,
          "EE supported_groups accepted");
    check(wn_CheckEncExt(ee_sni, sizeof(ee_sni), 1) == WOLFNANO_SUCCESS,
          "EE server_name accepted when SNI offered");
    check(wn_CheckEncExt(ee_sni, sizeof(ee_sni), 0) == WOLFNANO_E_UNEXPECTED_MSG,
          "EE server_name rejected when SNI not offered");
    check(wn_CheckEncExt(ee_sni_ne, sizeof(ee_sni_ne), 1)
              == WOLFNANO_E_UNEXPECTED_MSG,
          "EE non-empty server_name ack rejected");
    check(wn_CheckEncExt(ee_bad, sizeof(ee_bad), 1) == WOLFNANO_E_UNEXPECTED_MSG,
          "EE forbidden extension rejected");

    if (ekInit) {
        wc_ecc_free(&ek);
    }
#if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
    if (ek384Init) {
        wc_ecc_free(&ek384);
    }
#endif
#ifndef NO_RSA
    if (rsaInit) {
        wc_FreeRsaKey(&rsaKey);
    }
#endif
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
