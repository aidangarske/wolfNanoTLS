/* flight_order_test.c
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

/**
 * Adversarial-server tests for the encrypted-flight ordering gate
 * (wn_FlightOrder, src/wn_flight.h). RFC 8446 4.4 fixes the server flight as
 * EncryptedExtensions, [CertificateRequest], Certificate, CertificateVerify,
 * Finished. This drives whole message sequences through the gate and asserts
 * the legal ones are accepted and every out-of-order / duplicate / unknown
 * sequence is rejected with WOLFNANO_E_UNEXPECTED_MSG, mirroring what a
 * malformed or hostile server would send mid-handshake.
 */

#include "wn_flight.h"
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

/* Run a sequence through the gate; return the first non-success code, or
 * WOLFNANO_SUCCESS if the whole sequence is accepted. */
static int run_seq(const byte* seq, int n)
{
    int gotEE = 0;
    int gotCert = 0;
    int gotCv = 0;
    int ret = WOLFNANO_SUCCESS;
    int i;

    for (i = 0; (i < n) && (ret == WOLFNANO_SUCCESS); i++) {
        ret = wn_FlightOrder(seq[i], &gotEE, &gotCert, &gotCv);
    }

    return ret;
}

int main(void)
{
    static const byte certFlow[] = {
        WN_FLIGHT_EE, WN_FLIGHT_CERT, WN_FLIGHT_CERT_VFY, WN_FLIGHT_FINISHED
    };
    static const byte certReqFlow[] = {
        WN_FLIGHT_EE, WN_FLIGHT_CERT_REQ, WN_FLIGHT_CERT, WN_FLIGHT_CERT_VFY,
        WN_FLIGHT_FINISHED
    };
    static const byte certReqEarly[] = { WN_FLIGHT_CERT_REQ };
    static const byte certNoVfy[] = { WN_FLIGHT_EE, WN_FLIGHT_CERT };
    static const byte finishedFirst[] = { WN_FLIGHT_FINISHED };
    static const byte certBeforeEE[] = { WN_FLIGHT_CERT, WN_FLIGHT_EE };
    static const byte dupEE[] = { WN_FLIGHT_EE, WN_FLIGHT_EE };
    static const byte dupCert[] = {
        WN_FLIGHT_EE, WN_FLIGHT_CERT, WN_FLIGHT_CERT
    };
    static const byte cvNoCert[] = { WN_FLIGHT_EE, WN_FLIGHT_CERT_VFY };
    static const byte finBeforeCv[] = {
        WN_FLIGHT_EE, WN_FLIGHT_CERT, WN_FLIGHT_FINISHED
    };
    static const byte dupCv[] = {
        WN_FLIGHT_EE, WN_FLIGHT_CERT, WN_FLIGHT_CERT_VFY, WN_FLIGHT_CERT_VFY
    };
    static const byte unknownType[] = { WN_FLIGHT_EE, 99 };
    static const byte clientHelloType[] = { 1 };

    check(run_seq(certFlow, 4) == WOLFNANO_SUCCESS,
          "legal cert flight accepted");
    check(run_seq(certReqFlow, 5) == WOLFNANO_SUCCESS,
          "legal cert flight with CertificateRequest accepted");

    check(run_seq(certNoVfy, 2) == WOLFNANO_SUCCESS,
          "partial prefix (EE, Cert) accepted so far");

    check(run_seq(finishedFirst, 1) == WOLFNANO_E_UNEXPECTED_MSG,
          "Finished before CertificateVerify rejected");
    check(run_seq(certBeforeEE, 2) == WOLFNANO_E_UNEXPECTED_MSG,
          "Certificate before EncryptedExtensions rejected");
    check(run_seq(certReqEarly, 1) == WOLFNANO_E_UNEXPECTED_MSG,
          "CertificateRequest before EncryptedExtensions rejected");
    check(run_seq(dupEE, 2) == WOLFNANO_E_UNEXPECTED_MSG,
          "duplicate EncryptedExtensions rejected");
    check(run_seq(dupCert, 3) == WOLFNANO_E_UNEXPECTED_MSG,
          "duplicate Certificate rejected");
    check(run_seq(cvNoCert, 2) == WOLFNANO_E_UNEXPECTED_MSG,
          "CertificateVerify without Certificate rejected");
    check(run_seq(finBeforeCv, 3) == WOLFNANO_E_UNEXPECTED_MSG,
          "Finished before CertificateVerify (after Cert) rejected");
    check(run_seq(dupCv, 4) == WOLFNANO_E_UNEXPECTED_MSG,
          "duplicate CertificateVerify rejected");
    check(run_seq(unknownType, 2) == WOLFNANO_E_UNEXPECTED_MSG,
          "unknown handshake type rejected");
    check(run_seq(clientHelloType, 1) == WOLFNANO_E_UNEXPECTED_MSG,
          "client-side message type (ClientHello) rejected");

    if (fails == 0) {
        printf("flight_order_test: all checks passed\n");
    }
    else {
        printf("flight_order_test: %d FAILED\n", fails);
    }

    return fails == 0 ? 0 : 1;
}
