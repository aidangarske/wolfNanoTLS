/* x509_neg_test.c
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

static long find_pat(const byte* hay, long hayLen, const byte* pat, long patLen,
                     int last)
{
    long i;
    long hit = -1;

    for (i = 0; i + patLen <= hayLen; i++) {
        if (memcmp(hay + i, pat, (size_t)patLen) == 0) {
            hit = i;
            if (!last) {
                break;
            }
        }
    }
    return hit;
}

static int wolfssl_rejects(const byte* der, word32 len)
{
    DecodedCert dc;
    int rc;

    wc_InitDecodedCert(&dc, der, len, NULL);
    rc = wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
    wc_FreeDecodedCert(&dc);
    return rc != 0;
}

int main(void)
{
    static byte buf[4096];
    /* keyUsage extnID: OBJECT_ID(3) 2.5.29.15; ECDSA-with-SHA256 sig OID */
    static const byte ku_oid[]  = {0x06, 0x03, 0x55, 0x1D, 0x0F};
    static const byte sig_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
    const byte* ca = ca_ecc_cert_der_256;
    word32 caLen = (word32)sizeof_ca_ecc_cert_der_256;
    wn_X509Cert wn;
    long pos;
    word32 i;
    int badTrunc = 0;

    printf("wolfNanoTLS X.509 negative / adversarial tests\n");

    /* ---- invalid arguments ---- */
    check(wn_X509_Parse(NULL, ca, caLen) == WOLFNANO_E_INVALID_ARG,
          "NULL cert rejected");
    check(wn_X509_Parse(&wn, NULL, caLen) == WOLFNANO_E_INVALID_ARG,
          "NULL der rejected");
    check(wn_X509_Parse(&wn, ca, 0) == WOLFNANO_E_INVALID_ARG,
          "zero length rejected");
    check(wn_X509_Parse(&wn, ca, 1) == WOLFNANO_E_INVALID_ARG,
          "length 1 rejected");

    /* sanity: the unmutated cert parses */
    check(wn_X509_Parse(&wn, ca, caLen) == WOLFNANO_SUCCESS,
          "baseline ECC CA parses");

    /* ---- critical unknown extension fails closed ----
     * The ECC CA marks keyUsage critical; rewrite its OID to an unknown one,
     * so it becomes a critical extension wn_x509 does not recognize. */
    XMEMCPY(buf, ca, caLen);
    pos = find_pat(buf, (long)caLen, ku_oid, (long)sizeof(ku_oid), 0);
    check(pos >= 0, "located critical keyUsage extnID to corrupt");
    if (pos >= 0) {
        buf[pos + 4] = 0x7F;            /* 2.5.29.15 -> 2.5.29.127 (unknown) */
        check(wn_X509_Parse(&wn, buf, caLen) == WOLFNANO_E_X509_CRITEXT,
              "critical unknown extension rejected (fail-closed)");
        check(wolfssl_rejects(buf, caLen),
              "wolfSSL also rejects critical unknown extension");
    }

    /* ---- inner != outer signatureAlgorithm rejected ----
     * Flip the outer signatureAlgorithm OID (last occurrence) so it no longer
     * equals the tbsCertificate.signature AlgId. */
    XMEMCPY(buf, ca, caLen);
    pos = find_pat(buf, (long)caLen, sig_oid, (long)sizeof(sig_oid), 1);
    check(pos >= 0, "located outer signatureAlgorithm OID");
    if (pos >= 0) {
        buf[pos + 7] = 0x03;            /* SHA256 -> SHA384 OID: now mismatched */
        check(wn_X509_Parse(&wn, buf, caLen) < 0,
              "inner != outer signatureAlgorithm rejected");
        check(wolfssl_rejects(buf, caLen),
              "wolfSSL also rejects sigAlg mismatch");
    }

    /* ---- corrupted outer SEQUENCE tag rejected ---- */
    XMEMCPY(buf, ca, caLen);
    buf[0] = 0x00;
    check(wn_X509_Parse(&wn, buf, caLen) < 0, "bad outer tag rejected");

    /* ---- truncation: no proper prefix may parse as success ---- */
    for (i = 2; i < caLen; i++) {
        if (wn_X509_Parse(&wn, ca, i) == WOLFNANO_SUCCESS) {
            badTrunc++;
        }
    }
    check(badTrunc == 0, "no truncated prefix parses as success");

    /* ---- trailing bytes after the Certificate SEQUENCE rejected ----
     * A single DER cert must consume its whole buffer; wolfSSL stops at the
     * SEQUENCE length, wn_x509 fails closed on the extra byte. */
    XMEMCPY(buf, ca, caLen);
    buf[caLen] = 0x00;
    check(wn_X509_Parse(&wn, buf, caLen + 1) == WOLFNANO_E_X509_DECODE,
          "trailing byte after Certificate SEQUENCE rejected");

    printf("\n%s (%d failure%s)\n",
           fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
