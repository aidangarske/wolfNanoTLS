/* wn_x509.h
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

#ifndef WN_X509_H
#define WN_X509_H

#include "wolfnano.h"
#include <time.h>

/* key/curve/signature algorithm tags (internal; OID-byte matched) */
enum {
    WN_X509_KEY_UNKNOWN = 0,
    WN_X509_KEY_ECDSA,
    WN_X509_KEY_RSA,
    WN_X509_KEY_ED25519
};
enum {
    WN_X509_CURVE_NONE = 0,
    WN_X509_CURVE_P256,
    WN_X509_CURVE_P384,
    WN_X509_CURVE_P521
};
enum {
    WN_X509_SIG_UNKNOWN = 0,
    WN_X509_SIG_ECDSA_SHA256,
    WN_X509_SIG_ECDSA_SHA384,
    WN_X509_SIG_RSA_SHA256,
    WN_X509_SIG_RSA_SHA384,
    WN_X509_SIG_RSA_SHA512,
    WN_X509_SIG_ED25519
};

/* flags bitfield */
#define WN_X509_F_CA          0x0001
#define WN_X509_F_BC_SET      0x0002
#define WN_X509_F_BC_CRIT     0x0004
#define WN_X509_F_KU_SET      0x0010
#define WN_X509_F_KU_CRIT     0x0020
#define WN_X509_F_EKU_SET     0x0040
#define WN_X509_F_EKU_CRIT    0x0080
#define WN_X509_F_SAN_SET     0x0100
#define WN_X509_F_SAN_CRIT    0x0200

/* keyUsage / extKeyUsage bits the leaf check consults (wolfSSL KEYUSE_* /
 * EXTKEYUSE_* layout, redeclared so the native path needs no asn.h) */
#define WN_X509_KU_DIGITAL_SIG   0x0080
#define WN_X509_KU_KEY_CERT_SIGN 0x0004
#define WN_X509_EKU_SERVER_AUTH  0x02

#ifdef WOLFNANO_X509_HOSTNAME
#ifndef WN_X509_MAX_SAN
#define WN_X509_MAX_SAN 16      /* dNSName pool; overflow keeps the names that fit */
#endif
#ifndef WN_X509_MAX_DNS_NAME
#define WN_X509_MAX_DNS_NAME 255 /* longest CN/dNSName kept; longer fails closed */
#endif
typedef struct wn_X509San {
    const char* name;
    word16      len;
} wn_X509San;
#endif /* WOLFNANO_X509_HOSTNAME */

typedef struct wn_X509Cert {
    const byte* tbs;        word32 tbsLen;      /* tbsCertificate TLV: hash range */
    const byte* sig;        word32 sigLen;      /* raw signatureValue */
    const byte* pubKey;     word32 pubKeyLen;   /* raw subjectPublicKey */
    const byte* spki;       word32 spkiLen;     /* full SubjectPublicKeyInfo TLV */
#ifndef WOLFNANO_NO_X509_TIME
    const byte* notBefore;  word16 notBeforeLen;/* full Time TLV (tag+len+value) */
    const byte* notAfter;   word16 notAfterLen;
#endif
#ifdef WOLFNANO_X509_HOSTNAME
    const char* subjectCN;  word16 subjectCNLen;
#endif
    int   sigAlg;                               /* WN_X509_SIG_* */
    int   keyAlg;                               /* WN_X509_KEY_* */
    int   curve;                                /* WN_X509_CURVE_* */
    word16 flags;                               /* WN_X509_F_* bitfield */
    word16 keyUsage;                            /* wolfSSL KEYUSE_* layout */
    word16 extKeyUsage;                         /* EXTKEYUSE_* layout */
#ifdef WOLFNANO_X509_HOSTNAME
    int   sanCount;
    wn_X509San san[WN_X509_MAX_SAN];
#endif
} wn_X509Cert;

WOLFNANO_API int wn_X509_Parse(wn_X509Cert* cert, const byte* der,
                               word32 derLen);
WOLFNANO_API int wn_X509_VerifySignedBy(const wn_X509Cert* child,
                                        const wn_X509Cert* issuer);
#ifndef NO_RSA
/* Split a raw RSAPublicKey (SEQUENCE { n, e }) into n/e refs (shared with the
 * CertificateVerify raw-import path). */
WOLFNANO_LOCAL int wn_X509_RsaRawNE(const byte* in, word32 inLen,
                                    const byte** n, word32* nLen,
                                    const byte** e, word32* eLen);
#endif
/* Extract the raw subjectPublicKey bytes from a SubjectPublicKeyInfo TLV
 * (shared with the CertificateVerify raw-import path). */
WOLFNANO_LOCAL int wn_X509_SpkiRawKey(const byte* spki, word32 spkiLen,
                                      const byte** key, word32* keyLen);
/* Parse a SubjectPublicKeyInfo TLV's AlgorithmIdentifier into key type + curve
 * (binds the TLS SignatureScheme to the leaf key on the CertificateVerify path). */
WOLFNANO_LOCAL int wn_X509_SpkiKeyInfo(const byte* spki, word32 spkiLen,
                                       int* keyAlg, int* curve);
#ifndef WOLFNANO_NO_X509_TIME
WOLFNANO_API int wn_X509_TimeValid(const wn_X509Cert* cert, time_t now);
#endif

#endif /* WN_X509_H */
