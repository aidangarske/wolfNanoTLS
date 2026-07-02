/* x509_probe.c
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

#include "wn_x509.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PROBE_MAX_CHAIN 8
#define PROBE_MAX_CERT  8192

static const char* keyalg_name(int a)
{
    switch (a) {
        case WN_X509_KEY_ECDSA:   return "ECDSA";
        case WN_X509_KEY_RSA:     return "RSA";
        case WN_X509_KEY_ED25519: return "Ed25519";
        default:                  return "unknown";
    }
}

static const char* curve_name(int c)
{
    switch (c) {
        case WN_X509_CURVE_P256: return "P-256";
        case WN_X509_CURVE_P384: return "P-384";
        default:                 return "-";
    }
}

static const char* sigalg_name(int s)
{
    switch (s) {
        case WN_X509_SIG_ECDSA_SHA256: return "ECDSA-SHA256";
        case WN_X509_SIG_ECDSA_SHA384: return "ECDSA-SHA384";
        case WN_X509_SIG_RSA_SHA256:   return "RSA-SHA256";
        case WN_X509_SIG_RSA_SHA384:   return "RSA-SHA384";
        case WN_X509_SIG_RSA_SHA512:   return "RSA-SHA512";
        case WN_X509_SIG_ED25519:      return "Ed25519";
        default:                       return "unknown";
    }
}

static word32 load_der(const char* path, byte* buf, word32 max)
{
    FILE*  f = fopen(path, "rb");
    size_t n = 0;

    if (f != NULL) {
        n = fread(buf, 1, max, f);
        fclose(f);
    }
    return (word32)n;
}

/* Parse and report one chain (leaf first). Returns 0 on full success, else the
 * number of problems, so a caller/CI can fail on any parse or link error. */
static int probe_chain(const char* label, char* const files[], int n)
{
    static byte     der[PROBE_MAX_CHAIN][PROBE_MAX_CERT];
    static wn_X509Cert cert[PROBE_MAX_CHAIN];
    word32          len[PROBE_MAX_CHAIN];
    int             i;
    int             rc;
    int             problems = 0;

    printf("=== %s (%d cert%s) ===\n", label, n, (n == 1) ? "" : "s");
    if (n > PROBE_MAX_CHAIN) {
        n = PROBE_MAX_CHAIN;
        printf("  (chain truncated to %d)\n", PROBE_MAX_CHAIN);
    }

    for (i = 0; i < n; i++) {
        len[i] = load_der(files[i], der[i], (word32)sizeof(der[i]));
        if (len[i] == 0) {
            printf("  [%d] %s: LOAD FAILED\n", i, files[i]);
            problems++;
            continue;
        }
        rc = wn_X509_Parse(&cert[i], der[i], len[i]);
        if (rc != WOLFNANO_SUCCESS) {
            printf("  [%d] %s: PARSE FAILED rc=%d\n", i, files[i], rc);
            problems++;
            continue;
        }
        printf("  [%d] %-7s %-5s  sig=%-12s", i, keyalg_name(cert[i].keyAlg),
               curve_name(cert[i].curve), sigalg_name(cert[i].sigAlg));
#ifdef WOLFNANO_X509_HOSTNAME
        printf("  CN=%.*s SANs=%d",
               (cert[i].subjectCN != NULL) ? (int)cert[i].subjectCNLen : 1,
               (cert[i].subjectCN != NULL) ? cert[i].subjectCN : "-",
               cert[i].sanCount);
#endif
        printf("%s\n", ((cert[i].flags & WN_X509_F_CA) != 0) ? "  [CA]" : "");
    }

    /* leaf checks the TLS handshake performs: bind the SPKI key type (as
     * wn_CertVerify does) and check the validity window (as wn_VerifyChain does) */
    if ((n > 0) && (len[0] != 0)) {
        int ka = 0;
        int cv = 0;

        if (wn_X509_SpkiKeyInfo(cert[0].spki, cert[0].spkiLen, &ka, &cv) == 0) {
            printf("  leaf SPKI key: %s %s\n", keyalg_name(ka), curve_name(cv));
        }
        else {
            printf("  leaf SPKI: KEY-INFO FAILED\n");
            problems++;
        }
#ifndef WOLFNANO_NO_X509_TIME
        rc = wn_X509_TimeValid(&cert[0], (time_t)time(NULL));
        printf("  leaf validity @now: %s\n",
               (rc == WOLFNANO_SUCCESS) ? "in window" : "outside window");
#endif
    }

    /* per-hop signature linkage: child[i] signed by issuer[i+1] */
    for (i = 0; (i + 1) < n; i++) {
        if ((len[i] == 0) || (len[i + 1] == 0)) {
            continue;
        }
        rc = wn_X509_VerifySignedBy(&cert[i], &cert[i + 1]);
        printf("  link [%d]<-[%d]: %s\n", i, i + 1,
               (rc == WOLFNANO_SUCCESS) ? "OK" : "MISMATCH");
        if (rc != WOLFNANO_SUCCESS) {
            problems++;
        }
    }

    printf("  => %s\n\n", (problems == 0) ? "PASS" : "FAIL");
    return problems;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("usage: %s <leaf.der> [intermediate.der ...]\n", argv[0]);
        printf("  parses a DER cert chain (leaf first) with wn_x509 and reports\n");
        printf("  each field + per-hop signature links. Fetch a live chain with\n");
        printf("  examples/x509-probe.sh <host>. Exit != 0 on any parse/link error.\n");
        return 2;
    }
    return (probe_chain(argv[1], &argv[1], argc - 1) == 0) ? 0 : 1;
}
