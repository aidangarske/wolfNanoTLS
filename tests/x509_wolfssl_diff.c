/* x509_wolfssl_diff.c
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

/* Differential test against wolfSSL's X.509 parser: parse each embedded test
 * cert with BOTH wolfSSL (wc_ParseCert -> DecodedCert) and wn_X509_Parse, then
 * assert the fields match. Expected algorithm ids are MAPPED from wolfSSL's own
 * OID sums (no hardcoded per-cert assumptions), so any wolfCrypt test cert can
 * be added to the table and is checked field-for-field against wolfSSL. If
 * wn_x509 ever diverges from wolfSSL, this fails. */

#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_384
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_3072

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/certs_test.h>
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

static int eq(const byte* a, word32 aLen, const byte* b, word32 bLen)
{
    return (aLen == bLen) && (aLen == 0 || memcmp(a, b, aLen) == 0);
}

/* Map wolfSSL OID sums to the wn_x509 enums so "expected" comes from wolfSSL. */
static int map_key(word32 oid)
{
    switch (oid) {
        case ECDSAk:   return WN_X509_KEY_ECDSA;
        case RSAk:     return WN_X509_KEY_RSA;
        case ED25519k: return WN_X509_KEY_ED25519;
        default:       return WN_X509_KEY_UNKNOWN;
    }
}

static int map_curve(word32 oid)
{
    switch (oid) {
        case ECC_SECP256R1_OID: return WN_X509_CURVE_P256;
        case ECC_SECP384R1_OID: return WN_X509_CURVE_P384;
        case ECC_SECP521R1_OID: return WN_X509_CURVE_P521;
        default:                return WN_X509_CURVE_NONE;
    }
}

static int map_sig(word32 oid)
{
    switch (oid) {
        case CTC_SHA256wECDSA: return WN_X509_SIG_ECDSA_SHA256;
        case CTC_SHA384wECDSA: return WN_X509_SIG_ECDSA_SHA384;
        case CTC_SHA256wRSA:   return WN_X509_SIG_RSA_SHA256;
        case CTC_SHA384wRSA:   return WN_X509_SIG_RSA_SHA384;
        case CTC_SHA512wRSA:   return WN_X509_SIG_RSA_SHA512;
        case CTC_ED25519:      return WN_X509_SIG_ED25519;
        default:               return WN_X509_SIG_UNKNOWN;
    }
}

#ifdef WOLFNANO_X509_HOSTNAME
static int san_match(const wn_X509Cert* wn, DecodedCert* dc)
{
    DNS_entry* e;
    int i;
    int dnsN = 0;
    int found;

    for (e = dc->altNames; e != NULL; e = e->next) {
        if (e->type == ASN_DNS_TYPE) {
            dnsN++;
        }
    }
    if (dnsN != wn->sanCount) {
        return 0;
    }
    for (e = dc->altNames; e != NULL; e = e->next) {
        if (e->type != ASN_DNS_TYPE) {
            continue;
        }
        found = 0;
        for (i = 0; i < wn->sanCount; i++) {
            if (eq((const byte*)wn->san[i].name, wn->san[i].len,
                   (const byte*)e->name, (word32)e->len)) {
                found = 1;
                break;
            }
        }
        if (!found) {
            return 0;
        }
    }
    return 1;
}
#endif

static void diff_one(const byte* der, word32 derLen, const char* label)
{
    DecodedCert dc;
    wn_X509Cert wn;
    int stockRc, wnRc;
    char msg[112];

    wc_InitDecodedCert(&dc, der, derLen, NULL);
    stockRc = wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
    wnRc = wn_X509_Parse(&wn, der, derLen);

    snprintf(msg, sizeof(msg), "%s: both parse OK", label);
    check((stockRc == 0) && (wnRc == WOLFNANO_SUCCESS), msg);

    if ((stockRc == 0) && (wnRc == WOLFNANO_SUCCESS)) {
        snprintf(msg, sizeof(msg), "%s: tbs/pubkey/sig match wolfSSL", label);
        check(eq(wn.tbs, wn.tbsLen, dc.source + dc.certBegin,
                 dc.sigIndex - dc.certBegin) &&
              (eq(wn.pubKey, wn.pubKeyLen, dc.publicKey, dc.pubKeySize) ||
               eq(wn.spki, wn.spkiLen, dc.publicKey, dc.pubKeySize)) &&
              eq(wn.sig, wn.sigLen, dc.signature, dc.sigLength), msg);

        snprintf(msg, sizeof(msg), "%s: keyAlg/curve/sigAlg match wolfSSL", label);
        check((wn.keyAlg == map_key(dc.keyOID)) &&
              (wn.curve == map_curve(dc.pkCurveOID)) &&
              (wn.sigAlg == map_sig(dc.signatureOID)), msg);

        snprintf(msg, sizeof(msg), "%s: CA + KU + serverAuth match wolfSSL", label);
        check((((wn.flags & WN_X509_F_CA) != 0) == (dc.isCA != 0))
              && (wn.keyUsage == dc.extKeyUsage)
              && (wn.extKeyUsage ==
                  (dc.extExtKeyUsage & (EXTKEYUSE_SERVER_AUTH | EXTKEYUSE_ANY)))
              , msg);

#ifndef WOLFNANO_NO_X509_TIME
        snprintf(msg, sizeof(msg), "%s: validity dates match wolfSSL", label);
        check(eq(wn.notBefore, wn.notBeforeLen, dc.beforeDate,
                 (word32)dc.beforeDateLen) &&
              eq(wn.notAfter, wn.notAfterLen, dc.afterDate,
                 (word32)dc.afterDateLen), msg);
#endif
#ifdef WOLFNANO_X509_HOSTNAME
        snprintf(msg, sizeof(msg), "%s: CN + SAN dNSNames match wolfSSL", label);
        check(eq((const byte*)wn.subjectCN, wn.subjectCNLen,
                 (const byte*)dc.subjectCN, (word32)dc.subjectCNLen) &&
              san_match(&wn, &dc), msg);
#endif
    }

    wc_FreeDecodedCert(&dc);
}

int main(void)
{
    printf("wolfNanoTLS X.509 differential test vs wolfSSL wc_ParseCert\n");

#ifdef HAVE_ECC
    diff_one(ca_ecc_cert_der_256, (word32)sizeof_ca_ecc_cert_der_256,
             "ECC-P256 CA");
    diff_one(serv_ecc_der_256, (word32)sizeof_serv_ecc_der_256,
             "ECC-P256 server");
    diff_one(cliecc_cert_der_256, (word32)sizeof_cliecc_cert_der_256,
             "ECC-P256 client");
    diff_one(serv_ecc_rsa_der_256, (word32)sizeof_serv_ecc_rsa_der_256,
             "ECC-P256 server (RSA-signed)");
    diff_one(serv_ecc_comp_der_256, (word32)sizeof_serv_ecc_comp_der_256,
             "ECC-P256 server (compressed point)");
#if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
    diff_one(ca_ecc_cert_der_384, (word32)sizeof_ca_ecc_cert_der_384,
             "ECC-P384 CA");
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
    diff_one(ca_ed25519_cert, (word32)sizeof_ca_ed25519_cert,
             "Ed25519 CA");
    diff_one(server_ed25519_cert, (word32)sizeof_server_ed25519_cert,
             "Ed25519 server");
    diff_one(client_ed25519_cert, (word32)sizeof_client_ed25519_cert,
             "Ed25519 client");
#endif

#ifndef NO_RSA
    diff_one(ca_cert_der_2048, (word32)sizeof_ca_cert_der_2048,
             "RSA-2048 CA");
    diff_one(server_cert_der_2048, (word32)sizeof_server_cert_der_2048,
             "RSA-2048 server");
    diff_one(client_cert_der_2048, (word32)sizeof_client_cert_der_2048,
             "RSA-2048 client");
    diff_one(client_cert_der_3072, (word32)sizeof_client_cert_der_3072,
             "RSA-3072 client");
#endif

    printf("\n%s (%d failure%s)\n",
           fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
