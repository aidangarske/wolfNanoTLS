/* cert_gen_test.c
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

/* Generated-PKI coverage for wn_VerifyChain's constraint checks: build certs
 * with controlled CA flag, keyUsage, and extendedKeyUsage, then assert the
 * chain verifier accepts a well-formed leaf and rejects a non-serverAuth leaf,
 * a no-digitalSignature leaf, and a chain through a non-CA intermediate.
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <string.h>
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

/* Make an ECDSA-signed cert for subjKey, signed by issuerKey. issuerDer NULL
 * makes it self-signed (issuer name = subject name). Returns DER length. */
static int make_cert(byte* out, word32 outCap, ecc_key* subjKey,
                     ecc_key* issuerKey, const byte* issuerDer,
                     word32 issuerDerSz, const char* cn, int isCA,
                     const char* ku, const char* eku, WC_RNG* rng)
{
    Cert cert;
    int sz;

    wc_InitCert(&cert);
    XSTRNCPY(cert.subject.commonName, cn, CTC_NAME_SIZE - 1);
    cert.subject.commonName[CTC_NAME_SIZE - 1] = '\0';
    cert.sigType = CTC_SHA256wECDSA;
    cert.isCA = isCA;
    if (ku != NULL) {
        wc_SetKeyUsage(&cert, ku);
    }
    if (eku != NULL) {
        wc_SetExtKeyUsage(&cert, eku);
    }
    if (issuerDer != NULL) {
        wc_SetIssuerBuffer(&cert, issuerDer, (int)issuerDerSz);
    }
    else {
        XSTRNCPY(cert.issuer.commonName, cn, CTC_NAME_SIZE - 1);
        cert.issuer.commonName[CTC_NAME_SIZE - 1] = '\0';
    }

    sz = wc_MakeCert(&cert, out, outCap, NULL, subjKey, rng);
    if (sz >= 0) {
        sz = wc_SignCert(cert.bodySz, cert.sigType, out, outCap, NULL,
                         issuerKey, rng);
    }
    return sz;
}

int main(void)
{
    WC_RNG rng;
    ecc_key caKey, leafKey, midKey;
    byte caDer[1024], midDer[1024], leafDer[1024];
    byte spki[256];
    const byte* certs[2];
    word32 certLens[2];
    word32 spkiLen;
    int caLen, midLen, leafLen, rc;

    printf("wolfNano generated-PKI chain-constraint test\n");

    rc = wc_InitRng(&rng);
    rc |= wc_ecc_init(&caKey);   rc |= wc_ecc_make_key(&rng, 32, &caKey);
    rc |= wc_ecc_init(&leafKey); rc |= wc_ecc_make_key(&rng, 32, &leafKey);
    rc |= wc_ecc_init(&midKey);  rc |= wc_ecc_make_key(&rng, 32, &midKey);
    check(rc == 0, "RNG + key generation");

    caLen = make_cert(caDer, sizeof(caDer), &caKey, &caKey, NULL, 0,
                      "wolfNano Test CA", 1, "keyCertSign,digitalSignature",
                      NULL, &rng);
    check(caLen > 0, "self-signed CA generated");

    /* good leaf: serverAuth + digitalSignature, signed by the CA */
    leafLen = make_cert(leafDer, sizeof(leafDer), &leafKey, &caKey, caDer,
                        (word32)caLen, "good.example.com", 0,
                        "digitalSignature", "serverAuth", &rng);
    check(leafLen > 0, "good leaf generated");
    certs[0] = leafDer; certLens[0] = (word32)leafLen;
    spkiLen = sizeof(spki);
    rc = wn_VerifyChain(certs, certLens, 1, caDer, (word32)caLen, spki,
                        &spkiLen, NULL, NULL, 0);
    check(rc == WOLFNANO_SUCCESS, "valid serverAuth leaf accepted");

    /* leaf with clientAuth EKU only (no serverAuth) -> rejected */
    leafLen = make_cert(leafDer, sizeof(leafDer), &leafKey, &caKey, caDer,
                        (word32)caLen, "client.example.com", 0,
                        "digitalSignature", "clientAuth", &rng);
    certs[0] = leafDer; certLens[0] = (word32)leafLen;
    spkiLen = sizeof(spki);
    rc = wn_VerifyChain(certs, certLens, 1, caDer, (word32)caLen, spki,
                        &spkiLen, NULL, NULL, 0);
    check(rc == WOLFNANO_E_BAD_CERT, "leaf without serverAuth EKU rejected");

    /* leaf with keyUsage that omits digitalSignature -> rejected */
    leafLen = make_cert(leafDer, sizeof(leafDer), &leafKey, &caKey, caDer,
                        (word32)caLen, "noku.example.com", 0,
                        "keyEncipherment", "serverAuth", &rng);
    certs[0] = leafDer; certLens[0] = (word32)leafLen;
    spkiLen = sizeof(spki);
    rc = wn_VerifyChain(certs, certLens, 1, caDer, (word32)caLen, spki,
                        &spkiLen, NULL, NULL, 0);
    check(rc == WOLFNANO_E_BAD_CERT, "leaf without digitalSignature rejected");

    /* non-CA intermediate signed by CA, leaf signed by that intermediate */
    midLen = make_cert(midDer, sizeof(midDer), &midKey, &caKey, caDer,
                       (word32)caLen, "not-a-ca.example.com", 0,
                       "digitalSignature", NULL, &rng);
    leafLen = make_cert(leafDer, sizeof(leafDer), &leafKey, &midKey, midDer,
                        (word32)midLen, "leaf.example.com", 0,
                        "digitalSignature", "serverAuth", &rng);
    certs[0] = leafDer; certLens[0] = (word32)leafLen;
    certs[1] = midDer;  certLens[1] = (word32)midLen;
    spkiLen = sizeof(spki);
    rc = wn_VerifyChain(certs, certLens, 2, caDer, (word32)caLen, spki,
                        &spkiLen, NULL, NULL, 0);
    check(rc == WOLFNANO_E_BAD_CERT, "chain through non-CA intermediate rejected");

    wc_ecc_free(&caKey);
    wc_ecc_free(&leafKey);
    wc_ecc_free(&midKey);
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
