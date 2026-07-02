/* x509_negvec_test.c
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
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
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
    fclose(f);
    return (word32)n;
}

#define WN_EXP_ACCEPT 0
#define WN_EXP_REJECT 1
typedef struct {
    const char* file;
    const char* note;
    int         expect;       /* WN_EXP_ACCEPT / WN_EXP_REJECT */
    int         lenient;      /* 1: documented divergence (wolfSSL stricter) */
} negvec;

int main(void)
{
    static byte buf[8192];
    const char* dir = "tests/pki/neg/";
    negvec vecs[] = {
        { "server-badcnnull.der",  "CN embedded NUL (len-based match is the guard)",
          WN_EXP_ACCEPT, 0 },
        { "server-badaltnull.der", "SAN dNSName embedded NUL (spoofing)",
          WN_EXP_REJECT, 0 },
        { "server-badcn.der",      "odd CN",            WN_EXP_ACCEPT, 0 },
        { "server-badaltname.der", "odd SAN",           WN_EXP_ACCEPT, 0 },
        { "cert-bad-oid.der",      "malformed OID",     WN_EXP_ACCEPT, 1 },
        { "cert-bad-neg-int.der",  "negative INTEGER (serial not consumed)",
          WN_EXP_ACCEPT, 1 },
        { "cert-bad-utf8.der",     "bad UTF8 DirectoryString (never displayed)",
          WN_EXP_ACCEPT, 1 },
        { "server-cert-ecc-badsig.der", "ECC bad sig (caught by verify, not parse)",
          WN_EXP_ACCEPT, 0 },
        { "server-cert-rsa-badsig.der", "RSA bad sig (caught by verify, not parse)",
          WN_EXP_ACCEPT, 0 }
    };
    char path[128];
    word32 len;
    DecodedCert dc;
    wn_X509Cert wn;
    int stockRc, wnRc, wnAccept;
    size_t i;
    char msg[160];

    printf("wolfNanoTLS X.509 negative vectors (lifted from wolfSSL certs/test)\n");

    for (i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        snprintf(path, sizeof(path), "%s%s", dir, vecs[i].file);
        len = load(path, buf, (word32)sizeof(buf));
        snprintf(msg, sizeof(msg), "%s: loaded", vecs[i].file);
        check(len > 0, msg);
        if (len == 0) {
            continue;
        }

        wc_InitDecodedCert(&dc, buf, len, NULL);
        stockRc = wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
        wnRc = wn_X509_Parse(&wn, buf, len);
        wnAccept = (wnRc == WOLFNANO_SUCCESS);

        snprintf(msg, sizeof(msg), "%s: wn %s%s (wolfSSL=%d)", vecs[i].note,
                 wnAccept ? "accept" : "reject",
                 vecs[i].lenient ? " [intended divergence, wolfSSL rejects]" : "",
                 stockRc);
        check(wnAccept == (vecs[i].expect == WN_EXP_ACCEPT), msg);

        wc_FreeDecodedCert(&dc);
    }

    printf("\n%s (%d failure%s)\n",
           fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
