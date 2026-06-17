/* cert_test.c
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

/* X.509: parse a CA cert, then verify a server cert's signature against the
 * CA public key (the core chain-link check). Uses wolfSSL's embedded ECC test
 * certs. */

#define USE_CERT_BUFFERS_256

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/certs_test.h>
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
    DecodedCert ca;
    byte server[sizeof(serv_ecc_der_256)];
    int rc, verifyRc;

    printf("wolfNanoTLS X.509 cert verify test (ECC P-256 chain)\n");

    /* parse the CA cert to extract its public key (no chain to verify it) */
    wc_InitDecodedCert(&ca, ca_ecc_cert_der_256,
                       (word32)sizeof_ca_ecc_cert_der_256, NULL);
    rc = wc_ParseCert(&ca, CERT_TYPE, NO_VERIFY, NULL);
    check((rc == 0) && (ca.publicKey != NULL) && (ca.pubKeySize > 0),
          "parse CA cert + extract public key");

    /* verify the server cert is signed by the CA */
    verifyRc = CheckCertSignaturePubKey(serv_ecc_der_256,
                   (word32)sizeof_serv_ecc_der_256, NULL,
                   ca.publicKey, ca.pubKeySize, ca.keyOID);
    check(verifyRc == 0, "server cert signature verified by CA key");

    /* negative: tamper the server cert, signature must fail */
    XMEMCPY(server, serv_ecc_der_256, sizeof(serv_ecc_der_256));
    server[sizeof(server) - 1] ^= 0x01;
    verifyRc = CheckCertSignaturePubKey(server, (word32)sizeof(server), NULL,
                   ca.publicKey, ca.pubKeySize, ca.keyOID);
    check(verifyRc != 0, "tampered server cert rejected");

    wc_FreeDecodedCert(&ca);

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
