/* x509_cov_test.c
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

#include <wolfssl/wolfcrypt/settings.h>
#include "wn_x509.h"
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

static long find_pat(const byte* h, word32 hl, const byte* p, word32 pl)
{
    word32 i;

    for (i = 0; i + pl <= hl; i++) {
        if (memcmp(h + i, p, pl) == 0) {
            return (long)i;
        }
    }
    return -1;
}

static word32 load_der(const char* path, byte* buf, word32 max)
{
    FILE* f = fopen(path, "rb");
    size_t n = 0;

    if (f != NULL) {
        n = fread(buf, 1, max, f);
        if (((n == (size_t)max) && (fgetc(f) != EOF)) || ferror(f)) {
            n = 0;                          /* oversized/truncated: fail the load */
        }
        fclose(f);
    }
    return (word32)n;
}

/* every tamper of a self-signed cert must fail parse or self-verify (want 0) */
static int sweep(const byte* der, word32 len)
{
    static byte b[8192];
    static const byte muts[] = {0x00, 0xFF, 0x01, 0x30, 0x02};
    wn_X509Cert c;
    word32 i;
    word32 mi;
    int over = 0;

    if (len == 0 || len > (word32)sizeof(b)) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        for (mi = 0; mi < (word32)sizeof(muts); mi++) {
            if (der[i] == muts[mi]) {
                continue;
            }
            XMEMCPY(b, der, len);
            b[i] = muts[mi];
            if ((wn_X509_Parse(&c, b, len) == WOLFNANO_SUCCESS) &&
                (wn_X509_VerifySignedBy(&c, &c) == WOLFNANO_SUCCESS)) {
                over++;
            }
        }
    }
    return over;
}

static void expect_reject(const char* path, const char* name)
{
    static byte b[8192];
    wn_X509Cert c;
    word32 n = load_der(path, b, (word32)sizeof(b));

    check(n > 0 && wn_X509_Parse(&c, b, n) != WOLFNANO_SUCCESS, name);
}

int main(void)
{
    static byte der[8192];
    static byte tm[8192];
    static const byte utc[] = {0x17, 0x0D};
    static const byte ecdsa_oid[] = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
    static const byte rsa_oid[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B};
    static const byte oid_ku[]  = {0x06,0x03,0x55,0x1D,0x0F};
    static const byte oid_san[] = {0x06,0x03,0x55,0x1D,0x11};
    static const byte oid_eku[] = {0x06,0x03,0x55,0x1D,0x25};
    wn_X509Cert cert;
    wn_X509Cert zcert;
    word32 len;
    int keyAlg;
    int curve;
    long tp;
    word32 j;
    int patched;
    const byte* kp;
    word32 kl;
#ifndef NO_RSA
    const byte* np;
    word32 nl;
    const byte* ep;
    word32 el;
#endif

    printf("wolfNanoTLS X.509 coverage tests\n");

    /* ---- NULL-argument guards ---- */
    check(wn_X509_Parse(NULL, der, 1) == WOLFNANO_E_INVALID_ARG, "Parse NULL cert");
    check(wn_X509_VerifySignedBy(NULL, NULL) == WOLFNANO_E_INVALID_ARG, "Verify NULL");
    check(wn_X509_SpkiKeyInfo(NULL, 1, &keyAlg, &curve) == WOLFNANO_E_INVALID_ARG,
          "SpkiKeyInfo NULL spki");
    check(wn_X509_SpkiRawKey(NULL, 1, &kp, &kl) == WOLFNANO_E_INVALID_ARG,
          "SpkiRawKey NULL");
#ifndef NO_RSA
    check(wn_X509_RsaRawNE(NULL, 1, &np, &nl, &ep, &el) == WOLFNANO_E_INVALID_ARG,
          "RsaRawNE NULL");
#endif
#ifndef WOLFNANO_NO_X509_TIME
    check(wn_X509_TimeValid(NULL, 0) == WOLFNANO_E_INVALID_ARG, "TimeValid NULL cert");
#endif

    /* ---- RSA-SHA384 leaf: sig recognition + verify hash-map ---- */
    len = load_der("tests/pki/cov/rsa_sha384.der", der, sizeof(der));
    check(len > 0 && wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS,
          "RSA-SHA384 cert parses");
    if (len > 0) {
        check(wn_X509_VerifySignedBy(&cert, &cert) == WOLFNANO_SUCCESS,
              "RSA-SHA384 self-verify (SHA-384 hash-map)");
    }

    /* ---- RSA-SHA512 leaf ---- */
    len = load_der("tests/pki/cov/rsa_sha512.der", der, sizeof(der));
    check(len > 0 && wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS,
          "RSA-SHA512 cert parses");
    if (len > 0) {
        check(wn_X509_VerifySignedBy(&cert, &cert) == WOLFNANO_SUCCESS,
              "RSA-SHA512 self-verify (SHA-512 hash-map)");
    }

    /* ---- feature-rich ECDSA leaf: 2-byte keyUsage, critical anyEKU + SAN ---- */
    len = load_der("tests/pki/cov/feat_ecc.der", der, sizeof(der));
    check(len > 0 && wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS,
          "feature-rich ECDSA cert parses (2-byte KU, crit EKU/SAN)");

    /* ---- Ed25519 self-signed sweep: exercises the Ed verify path ---- */
    len = load_der("tests/pki/server/ed-cert.der", der, sizeof(der));
    check(len > 0, "ed-cert.der loaded");
    if (len > 0) {
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS &&
              wn_X509_VerifySignedBy(&cert, &cert) == WOLFNANO_SUCCESS,
              "Ed25519 cert parses and self-verifies");
        check(sweep(der, len) == 0, "Ed25519 sweep: tamper fails parse or verify");
    }

    /* ---- unknown but structurally-valid sig alg: parses, then verify rejects at
     * wn_SigAlgMatchesKey (before the key-type switch) ---- */
    len = load_der("tests/pki/server/ec-cert.der", der, sizeof(der));
    patched = 0;
    for (j = 0; len > 0 && j + (word32)sizeof(ecdsa_oid) <= len; j++) {
        if (memcmp(der + j, ecdsa_oid, sizeof(ecdsa_oid)) == 0) {
            der[j + 7] = 0x09;              /* ecdsa-with-SHA256 -> unknown OID */
            patched++;
        }
    }
    check(patched == 2, "patched inner+outer ECDSA sig OID to unknown");
    if (patched == 2) {
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS &&
              wn_X509_VerifySignedBy(&cert, &cert) != WOLFNANO_SUCCESS,
              "unknown ECDSA sig alg: parses, verify rejects at sig/key match");
    }

    /* ---- RSA cert relabeled sha256WithRSA -> sha384WithRSA (inner+outer): the
     * declared alg no longer matches the SHA-256 signature, so verify rejects ---- */
#ifndef NO_RSA
    len = load_der("tests/pki/server/rsa-cert.der", der, sizeof(der));
    patched = 0;
    for (j = 0; len > 0 && j + (word32)sizeof(rsa_oid) <= len; j++) {
        if (memcmp(der + j, rsa_oid, sizeof(rsa_oid)) == 0) {
            der[j + 8] = 0x0C;             /* sha256WithRSA -> sha384WithRSA */
            patched++;
        }
    }
    check(patched == 2, "patched inner+outer RSA sig OID to SHA-384");
    if (patched == 2) {
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS &&
              wn_X509_VerifySignedBy(&cert, &cert) != WOLFNANO_SUCCESS,
              "RSA sigAlg relabeled to SHA-384 (signature mismatch) rejected");
    }

    /* ---- RSA signatureAlgorithm with non-NULL parameters rejected ---- */
    len = load_der("tests/pki/server/rsa-cert.der", der, sizeof(der));
    patched = 0;
    for (j = 0; len > 0 && j + (word32)sizeof(rsa_oid) + 1 <= len; j++) {
        if (memcmp(der + j, rsa_oid, sizeof(rsa_oid)) == 0 &&
            der[j + (word32)sizeof(rsa_oid)] == 0x05) {   /* NULL tag after OID */
            der[j + (word32)sizeof(rsa_oid)] = 0x06;      /* -> not NULL */
            patched++;
        }
    }
    check(patched == 2, "located RSA sigAlg NULL parameter (inner+outer)");
    if (patched == 2) {
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_E_X509_DECODE,
              "RSA sigAlg with non-NULL params rejected");
    }
#endif

    /* ---- duplicate-extension rejects: relabel a later ext to match an earlier
     * recognized one; feat_ecc ext order is BC, KU, EKU, SAN ---- */
    len = load_der("tests/pki/cov/feat_ecc.der", der, sizeof(der));
    tp = find_pat(der, len, oid_ku, sizeof(oid_ku));    /* keyUsage -> BC (dup BC) */
    check(tp >= 0, "located keyUsage OID for dup-BC");
    if (tp >= 0) {
        der[tp + 4] = 0x13;
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_E_X509_DECODE,
              "duplicate basicConstraints rejected");
    }
    len = load_der("tests/pki/cov/feat_ecc.der", der, sizeof(der));
    tp = find_pat(der, len, oid_eku, sizeof(oid_eku));  /* extKeyUsage -> KU (dup KU) */
    check(tp >= 0, "located extKeyUsage OID for dup-KU");
    if (tp >= 0) {
        der[tp + 4] = 0x0F;
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_E_X509_DECODE,
              "duplicate keyUsage rejected");
    }
    len = load_der("tests/pki/cov/feat_ecc.der", der, sizeof(der));
    tp = find_pat(der, len, oid_san, sizeof(oid_san));  /* SAN -> EKU (dup EKU) */
    check(tp >= 0, "located subjectAltName OID for dup-EKU");
    if (tp >= 0) {
        der[tp + 4] = 0x25;
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_E_X509_DECODE,
              "duplicate extKeyUsage rejected");
    }

    /* ---- structurally-malformed certs (DER-surgery generated) rejected ---- */
    expect_reject("tests/pki/cov/mal_empty_eku.der", "empty EKU SEQUENCE rejected");
    expect_reject("tests/pki/cov/mal_empty_san.der", "empty SAN SEQUENCE rejected");
    expect_reject("tests/pki/cov/mal_empty_exts.der", "empty extensions SEQUENCE rejected");
    expect_reject("tests/pki/cov/mal_dup_san.der", "duplicate SAN rejected");
    expect_reject("tests/pki/cov/mal_bc_trailing.der", "basicConstraints trailing byte rejected");
    expect_reject("tests/pki/cov/mal_sigalg_trailing.der", "ECDSA sigAlg trailing bytes rejected");
    expect_reject("tests/pki/cov/mal_ed_params.der", "Ed25519 SPKI with params rejected");
#ifndef NO_RSA
    len = load_der("tests/pki/cov/mal_rsa_badkey.der", der, sizeof(der));
    check(len > 0, "mal_rsa_badkey.der loaded");
    if (len > 0) {
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS &&
              wn_X509_VerifySignedBy(&cert, &cert) != WOLFNANO_SUCCESS,
              "RSA modulus too large for wc_RsaPublicKeyDecodeRaw rejected");
    }
#endif
    len = load_der("tests/pki/cov/mal_uniqueid.der", der, sizeof(der));
    check(len > 0, "mal_uniqueid.der loaded");
    if (len > 0) {
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS,
              "cert with subjectUniqueID parses (v2 uniqueID skipped)");
    }
#ifndef WOLFNANO_NO_X509_TIME
    len = load_der("tests/pki/cov/gentime.der", der, sizeof(der));
    check(len > 0, "gentime.der loaded");
    if (len > 0) {
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS &&
              wn_X509_TimeValid(&cert, (time_t)2650000000LL) == WOLFNANO_SUCCESS,
              "GeneralizedTime validity parsed and valid");
    }
#endif

    /* ---- malformed validity Time values rejected by TimeValid ---- */
#ifndef WOLFNANO_NO_X509_TIME
    len = load_der("tests/pki/server/ec-cert.der", der, sizeof(der));
    tp = (len > 0) ? find_pat(der, len, utc, sizeof(utc)) : -1;
    check(tp >= 0, "located UTCTime notBefore");
    if (tp >= 0) {
        XMEMCPY(tm, der, len);
        tm[tp + 2] = 0x2F;                  /* first time digit -> non-digit */
        check(wn_X509_Parse(&cert, tm, len) == WOLFNANO_SUCCESS &&
              wn_X509_TimeValid(&cert, 0) != WOLFNANO_SUCCESS,
              "non-digit in UTCTime rejected");
        XMEMCPY(tm, der, len);
        tm[tp + 14] = 0x59;                 /* 'Z' terminator -> 'Y' */
        check(wn_X509_Parse(&cert, tm, len) == WOLFNANO_SUCCESS &&
              wn_X509_TimeValid(&cert, 0) != WOLFNANO_SUCCESS,
              "UTCTime without Z terminator rejected");
        XMEMCPY(tm, der, len);
        tm[tp + 4] = 0x31; tm[tp + 5] = 0x33;   /* month digits -> "13" (out of range) */
        check(wn_X509_Parse(&cert, tm, len) == WOLFNANO_SUCCESS &&
              wn_X509_TimeValid(&cert, 0) != WOLFNANO_SUCCESS,
              "UTCTime month out of range rejected");
    }
    len = load_der("tests/pki/cov/mal_time_badlen.der", der, sizeof(der));
    check(len > 0, "mal_time_badlen.der loaded");
    if (len > 0) {
        check(wn_X509_Parse(&cert, der, len) == WOLFNANO_SUCCESS &&
              wn_X509_TimeValid(&cert, 0) != WOLFNANO_SUCCESS,
              "Time of wrong length (not UTCTime-13 / GenTime-15) rejected");
    }
    /* public API on a zeroed cert: notBefore == NULL reaches the guard */
    XMEMSET(&zcert, 0, sizeof(zcert));
    check(wn_X509_TimeValid(&zcert, 0) != WOLFNANO_SUCCESS,
          "zeroed cert: TimeValid rejects (NULL Time TLV)");
#endif

    printf("\n%s (%d failure%s)\n",
           fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
