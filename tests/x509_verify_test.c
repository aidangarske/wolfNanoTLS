/* x509_verify_test.c
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

#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048

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

static word32 load(const char* path, byte* buf, word32 max)
{
    FILE* f = fopen(path, "rb");
    size_t n;

    if (f == NULL) {
        return 0;
    }
    n = fread(buf, 1, max, f);
    if (((n == (size_t)max) && (fgetc(f) != EOF)) || ferror(f)) {
        n = 0;                              /* oversized/truncated: fail the load */
    }
    fclose(f);
    return (word32)n;
}

static void verify_pair(const byte* child, word32 cl, const byte* ca,
                        word32 al, const char* label)
{
    static byte buf[4096];
    wn_X509Cert cWn, aWn;
#ifndef WOLFSSL_NO_MALLOC
    DecodedCert aDc;                         /* asn.c reference: needs heap */
#endif
    int tparse, tverify, parsedOk;
    char msg[112];

    snprintf(msg, sizeof(msg), "%s: parse child + issuer", label);
    parsedOk = (wn_X509_Parse(&aWn, ca, al) == WOLFNANO_SUCCESS) &&
               (wn_X509_Parse(&cWn, child, cl) == WOLFNANO_SUCCESS);
    check(parsedOk, msg);
    if (!parsedOk) {
        return;                             /* don't verify with unparsed certs */
    }

    snprintf(msg, sizeof(msg), "%s: child verified by issuer (wn_x509)", label);
    check(wn_X509_VerifySignedBy(&cWn, &aWn) == WOLFNANO_SUCCESS, msg);

#ifndef WOLFSSL_NO_MALLOC
    wc_InitDecodedCert(&aDc, ca, al, NULL);
    wc_ParseCert(&aDc, CERT_TYPE, NO_VERIFY, NULL);
    snprintf(msg, sizeof(msg), "%s: wolfSSL CheckCertSignaturePubKey agrees", label);
    check(CheckCertSignaturePubKey(child, cl, NULL, aDc.publicKey,
              aDc.pubKeySize, aDc.keyOID) == 0, msg);
    wc_FreeDecodedCert(&aDc);
#endif

    /* tamper a signature byte: the child must no longer verify (reject at
     * parse if the signature DER breaks, else at verification) */
    XMEMCPY(buf, child, cl);
    buf[cl - 8] ^= 0xFF;
    tparse = wn_X509_Parse(&cWn, buf, cl);
    tverify = (tparse == WOLFNANO_SUCCESS) ? wn_X509_VerifySignedBy(&cWn, &aWn)
                                           : tparse;
    snprintf(msg, sizeof(msg), "%s: tampered child rejected", label);
    check(tverify != WOLFNANO_SUCCESS, msg);
}

static void time_test(void)
{
    static byte buf[4096];
    wn_X509Cert wn;
    word32 n;

    /* tests/pki/server/ec-cert.der is valid 2025-01-01 .. 2045-01-01 */
    n = load("tests/pki/server/ec-cert.der", buf, (word32)sizeof(buf));
    check((n > 0) && (wn_X509_Parse(&wn, buf, n) == WOLFNANO_SUCCESS),
          "TimeValid: parse known-validity cert");
    if (n == 0) {
        return;
    }
    check(wn_X509_TimeValid(&wn, (time_t)1767225600LL) == WOLFNANO_SUCCESS,
          "TimeValid: in window (2026) accepted");
    check(wn_X509_TimeValid(&wn, (time_t)1577836800LL) == WOLFNANO_E_BAD_CERT,
          "TimeValid: before notBefore (2020) rejected");
    check(wn_X509_TimeValid(&wn, (time_t)2524608000LL) == WOLFNANO_E_BAD_CERT,
          "TimeValid: after notAfter (2050) rejected");
    check(wn_X509_TimeValid(&wn, (time_t)0) == WOLFNANO_E_BAD_CERT,
          "TimeValid: epoch 0 (1970) before notBefore rejected (no ambient clock)");
}

int main(void)
{
    printf("wolfNanoTLS X.509 verify + time tests\n");

#ifdef HAVE_ECC
    verify_pair(serv_ecc_der_256, (word32)sizeof_serv_ecc_der_256,
                ca_ecc_cert_der_256, (word32)sizeof_ca_ecc_cert_der_256,
                "ECC-P256");
#endif
#ifndef NO_RSA
    verify_pair(server_cert_der_2048, (word32)sizeof_server_cert_der_2048,
                ca_cert_der_2048, (word32)sizeof_ca_cert_der_2048, "RSA-2048");
#endif
#ifdef HAVE_ED25519
    verify_pair(server_ed25519_cert, (word32)sizeof_server_ed25519_cert,
                ca_ed25519_cert, (word32)sizeof_ca_ed25519_cert, "Ed25519");
#endif

    time_test();

    printf("\n%s (%d failure%s)\n",
           fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
