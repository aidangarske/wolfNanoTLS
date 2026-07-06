/* wn_x509.c
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

#ifdef WOLFNANO_X509
    #include <wolfssl/wolfcrypt/hash.h>
    #ifdef HAVE_ECC
        #include <wolfssl/wolfcrypt/ecc.h>
    #endif
    #ifndef NO_RSA
        #include <wolfssl/wolfcrypt/rsa.h>
        #include <wolfssl/wolfcrypt/asn_public.h>
    #endif
    #ifdef HAVE_ED25519
        #include <wolfssl/wolfcrypt/ed25519.h>
    #endif
#endif

enum {
    WN_ASN_BOOLEAN          = 0x01,
    WN_ASN_INTEGER          = 0x02,
    WN_ASN_BIT_STRING       = 0x03,
    WN_ASN_OCTET_STRING     = 0x04,
    WN_ASN_NULL             = 0x05,
    WN_ASN_OBJECT_ID        = 0x06,
    WN_ASN_UTF8_STRING      = 0x0C,
    WN_ASN_PRINTABLE_STRING = 0x13,
    WN_ASN_T61_STRING       = 0x14,
    WN_ASN_IA5_STRING       = 0x16,
    WN_ASN_UTC_TIME         = 0x17,
    WN_ASN_GEN_TIME         = 0x18,
    WN_ASN_SET              = 0x11,
    WN_ASN_SEQUENCE         = 0x10,
    WN_ASN_CONSTRUCTED      = 0x20,
    WN_ASN_CONTEXT_SPECIFIC = 0x80,
    WN_ASN_LONG_LENGTH      = 0x80
};

#define WN_ASN_SEQ    (WN_ASN_SEQUENCE | WN_ASN_CONSTRUCTED)
#define WN_ASN_SET_OF (WN_ASN_SET | WN_ASN_CONSTRUCTED)
#define WN_ASN_CTX0   (WN_ASN_CONTEXT_SPECIFIC | WN_ASN_CONSTRUCTED)
#define WN_ASN_CTX1   (WN_ASN_CONTEXT_SPECIFIC | WN_ASN_CONSTRUCTED | 0x01)
#define WN_ASN_CTX2   (WN_ASN_CONTEXT_SPECIFIC | WN_ASN_CONSTRUCTED | 0x02)
#define WN_ASN_CTX3   (WN_ASN_CONTEXT_SPECIFIC | WN_ASN_CONSTRUCTED | 0x03)
#define WN_ASN_UID1   (WN_ASN_CONTEXT_SPECIFIC | 0x01)  /* [1] issuerUniqueID (primitive) */
#define WN_ASN_UID2   (WN_ASN_CONTEXT_SPECIFIC | 0x02)  /* [2] subjectUniqueID (primitive) */
#define WN_ASN_SAN_DNS (WN_ASN_CONTEXT_SPECIFIC | 0x02)  /* GeneralName [2] dNSName */

/* matches wolfSSL EXTKEYUSE_* (asn.h) so wn_X509Cert.extKeyUsage is diff-equal */
#define WN_EXTKEYUSE_ANY         0x01
#define WN_EXTKEYUSE_SERVER_AUTH 0x02

/* seen-bits for VERIFY_AND_SET_OID-style duplicate-extension rejection */
#define WN_EXT_SEEN_BC  0x01
#define WN_EXT_SEEN_KU  0x02
#define WN_EXT_SEEN_EKU 0x04
#define WN_EXT_SEEN_SAN 0x08

/* OID value bytes (content after tag+len) for the algorithms wolfNano accepts. */
static const byte WN_OID_EC_PUBKEY[]   = {0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01};
#ifndef NO_RSA
static const byte WN_OID_RSA_ENC[]     = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};
#endif
#ifdef HAVE_ED25519
static const byte WN_OID_ED25519[]     = {0x2B,0x65,0x70};
#endif
static const byte WN_OID_P256[]        = {0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
#ifdef HAVE_ECC384
static const byte WN_OID_P384[]        = {0x2B,0x81,0x04,0x00,0x22};
#endif
static const byte WN_OID_ECDSA_SHA256[]= {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
#if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
static const byte WN_OID_ECDSA_SHA384[]= {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x03};
#endif
#ifndef NO_RSA
static const byte WN_OID_RSA_SHA256[]  = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B};
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_SHA384)
static const byte WN_OID_RSA_SHA384[]  = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0C};
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_SHA512)
static const byte WN_OID_RSA_SHA512[]  = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0D};
#endif
/* certificate extension OIDs (recognized always so critical-known never trips
 * the unknown-critical fail-closed, even when storage is gated out) */
static const byte WN_OID_EXT_BC[]      = {0x55,0x1D,0x13};   /* basicConstraints */
static const byte WN_OID_EXT_KU[]      = {0x55,0x1D,0x0F};   /* keyUsage */
static const byte WN_OID_EXT_EKU[]     = {0x55,0x1D,0x25};   /* extKeyUsage */
static const byte WN_OID_EXT_SAN[]     = {0x55,0x1D,0x11};   /* subjectAltName */
static const byte WN_OID_EKU_SRVAUTH[] = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01};
static const byte WN_OID_EKU_ANY[]     = {0x55,0x1D,0x25,0x00};  /* anyExtendedKeyUsage */

/* DER length decode. Returns the length (>= 0) on success, WOLFNANO_E_X509_DECODE
 * on error. Rejects BER indefinite length, > 3 length bytes, and out-of-bounds.
 * Lifted from wolfTPM TPM2_ASN_GetLength_ex. */
static int wn_Asn_GetLength(const byte* in, word32* inOutIdx, int* len,
                            word32 maxIdx, int check)
{
    int    ret = 0;
    int    length = 0;
    word32 idx = *inOutIdx;
    word32 bytes;
    byte   b;

    *len = 0;

    if ((idx + 1) > maxIdx) {
        ret = WOLFNANO_E_X509_DECODE;
    }

    if (ret == 0) {
        b = in[idx++];
        if (b >= WN_ASN_LONG_LENGTH) {
            bytes = (word32)(b & 0x7F);
            if ((bytes == 0) || (bytes > 3) || ((idx + bytes) > maxIdx) ||
                (in[idx] == 0x00)) {        /* DER: no leading-zero length octet */
                ret = WOLFNANO_E_X509_DECODE;
            }
            else {
                while (bytes-- > 0) {
                    length = (length << 8) | in[idx++];
                }
                if (length < 0x80) {        /* DER: long form only for len >= 128 */
                    ret = WOLFNANO_E_X509_DECODE;
                }
            }
        }
        else {
            length = b;
        }
    }

    if ((ret == 0) && check && ((idx + (word32)length) > maxIdx)) {
        ret = WOLFNANO_E_X509_DECODE;
    }

    if (ret == 0) {
        *inOutIdx = idx;
        if (length > 0) {
            *len = length;
        }
        ret = length;
    }

    return ret;
}

/* Decode an expected tag + length. Returns the content length (>= 0) on success,
 * WOLFNANO_E_X509_DECODE on tag mismatch or buffer error. Lifted from wolfTPM
 * TPM2_ASN_GetHeader. */
static int wn_Asn_GetHeader(const byte* in, byte tag, word32* inOutIdx, int* len,
                            word32 maxIdx)
{
    int    ret = 0;
    int    length = 0;
    word32 idx = *inOutIdx;

    if ((idx + 1) > maxIdx) {
        ret = WOLFNANO_E_X509_DECODE;
    }

    if ((ret == 0) && (in[idx++] != tag)) {
        ret = WOLFNANO_E_X509_DECODE;
    }

    if (ret == 0) {
        ret = wn_Asn_GetLength(in, &idx, &length, maxIdx, 1);
    }

    if (ret >= 0) {
        *len = length;
        *inOutIdx = idx;
        ret = length;
    }

    return ret;
}

/* wn_Asn_GetHeader plus the common "this TLV must fill its parent exactly"
 * constraint: the value ends precisely at maxIdx (no trailing bytes). Folds the
 * repeated post-header bounds check into one call. */
static int wn_Asn_GetHeaderExact(const byte* in, byte tag, word32* inOutIdx,
                                 int* len, word32 maxIdx)
{
    int ret = wn_Asn_GetHeader(in, tag, inOutIdx, len, maxIdx);

    if ((ret >= 0) && ((*inOutIdx + (word32)*len) != maxIdx)) {
        ret = WOLFNANO_E_X509_DECODE;
    }
    return ret;
}

/* Decode a BIT STRING and return its content after the mandatory DER leading
 * unused-bits octet (which must be present and zero). Advances *idx past the
 * value. Shared by the SPKI-key and signatureValue paths. */
static int wn_Asn_GetBitString(const byte* der, word32* idx, word32 end,
                               const byte** out, word32* outLen)
{
    int rc;
    int len = 0;

    rc = wn_Asn_GetHeader(der, WN_ASN_BIT_STRING, idx, &len, end);
    if ((rc >= 0) && ((len < 1) || (der[*idx] != 0x00))) {
        rc = WOLFNANO_E_X509_DECODE;    /* DER: leading zero unused-bits octet */
    }
    if (rc >= 0) {
        (*idx)++;                       /* drop BIT STRING unused-bits octet */
        len--;
        *out = der + *idx;
        *outLen = (word32)len;
        *idx += (word32)len;
        rc = 0;
    }
    return rc;
}

/* Byte-equality for public data (OIDs, algorithm ids, DigestInfo). These are not
 * secrets, so the fast variable-time library compare is correct here;
 * ConstantCompare is reserved for MAC/secret comparisons on the handshake path. */
static int wn_MemEq(const byte* a, const byte* b, word32 len)
{
    return XMEMCMP(a, b, len) == 0; /* ct-public: OIDs/DigestInfo, not secrets */
}

static int wn_OidEq(const byte* p, int len, const byte* want, word32 wantLen)
{
    return ((word32)len == wantLen) && wn_MemEq(p, want, wantLen);
}

/* Extract the raw subjectPublicKey (BIT STRING content) from a full SPKI TLV:
 * SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING }. Lets the
 * CertificateVerify path load a key from an SPKI without asn.c. */
WOLFNANO_LOCAL int wn_X509_SpkiRawKey(const byte* spki, word32 spkiLen,
                                      const byte** key, word32* keyLen)
{
    word32 idx = 0;
    int    ret = 0;
    int    len = 0;
    int    algLen = 0;

    if ((spki == NULL) || (key == NULL) || (keyLen == NULL)) {
        return WOLFNANO_E_INVALID_ARG;
    }
    ret = wn_Asn_GetHeader(spki, WN_ASN_SEQ, &idx, &len, spkiLen);
    if (ret >= 0) {
        ret = wn_Asn_GetHeader(spki, WN_ASN_SEQ, &idx, &algLen, spkiLen);
    }
    if (ret >= 0) {
        idx += (word32)algLen;              /* skip AlgorithmIdentifier */
        ret = wn_Asn_GetBitString(spki, &idx, spkiLen, key, keyLen);
    }

    return (ret >= 0) ? 0 : ret;
}

#ifdef WOLFNANO_X509_HOSTNAME
static int wn_HasNul(const byte* p, word32 n)
{
    /* public identity bytes (CN/SAN); memchr is word-at-a-time and early-exits */
    return memchr(p, 0, n) != NULL;
}
#endif

static int wn_KeyAlgFromOid(const byte* p, int len)
{
    int alg = WN_X509_KEY_UNKNOWN;

    if (wn_OidEq(p, len, WN_OID_EC_PUBKEY, sizeof(WN_OID_EC_PUBKEY))) {
        alg = WN_X509_KEY_ECDSA;
    }
#ifndef NO_RSA
    else if (wn_OidEq(p, len, WN_OID_RSA_ENC, sizeof(WN_OID_RSA_ENC))) {
        alg = WN_X509_KEY_RSA;
    }
#endif
#ifdef HAVE_ED25519
    else if (wn_OidEq(p, len, WN_OID_ED25519, sizeof(WN_OID_ED25519))) {
        alg = WN_X509_KEY_ED25519;
    }
#endif

    return alg;
}

static int wn_CurveFromOid(const byte* p, int len)
{
    int curve = WN_X509_CURVE_NONE;

    if (wn_OidEq(p, len, WN_OID_P256, sizeof(WN_OID_P256))) {
        curve = WN_X509_CURVE_P256;
    }
#ifdef HAVE_ECC384
    else if (wn_OidEq(p, len, WN_OID_P384, sizeof(WN_OID_P384))) {
        curve = WN_X509_CURVE_P384;
    }
#endif

    return curve;
}

/* From an AlgorithmIdentifier OID (and its parameters), fill the key type and
 * curve, and validate the parameter shape (RFC 5280 / asn.c): id-ecPublicKey
 * carries a namedCurve OID filling the AlgId; rsaEncryption carries NULL;
 * Ed25519 carries no parameters. Shared by SPKI parsing and wn_X509_SpkiKeyInfo. */
static int wn_ParseAlgIdOids(const byte* der, word32* idx, word32 algEnd,
                             int* keyAlg, int* curve)
{
    int rc;
    int oidLen = 0;

    rc = wn_Asn_GetHeader(der, WN_ASN_OBJECT_ID, idx, &oidLen, algEnd);
    if (rc >= 0) {
        *keyAlg = wn_KeyAlgFromOid(der + *idx, oidLen);
        *idx += (word32)oidLen;
    }
    if (rc >= 0) {
        if (*keyAlg == WN_X509_KEY_ECDSA) {
            rc = wn_Asn_GetHeader(der, WN_ASN_OBJECT_ID, idx, &oidLen, algEnd);
            if (rc >= 0) {
                *curve = wn_CurveFromOid(der + *idx, oidLen);
                *idx += (word32)oidLen;
                if (*idx != algEnd) {       /* namedCurve must fill the AlgId */
                    rc = WOLFNANO_E_X509_DECODE;
                }
            }
        }
        else if (*keyAlg == WN_X509_KEY_RSA) {
            rc = wn_Asn_GetHeader(der, WN_ASN_NULL, idx, &oidLen, algEnd);
            if ((rc >= 0) && ((oidLen != 0) || (*idx != algEnd))) {
                rc = WOLFNANO_E_X509_DECODE; /* rsaEncryption params MUST be NULL */
            }
        }
#ifdef HAVE_ED25519
        else if (*keyAlg == WN_X509_KEY_ED25519) {
            if (*idx != algEnd) {           /* Ed25519 takes no parameters */
                rc = WOLFNANO_E_X509_DECODE;
            }
        }
#endif
    }
    return rc;
}

/* Parse only the AlgorithmIdentifier of a full SPKI TLV into key type + curve
 * (WN_X509_KEY_* / WN_X509_CURVE_*). Lets the CertificateVerify path bind the
 * TLS SignatureScheme to the leaf's declared key without a full re-parse. */
WOLFNANO_LOCAL int wn_X509_SpkiKeyInfo(const byte* spki, word32 spkiLen,
                                       int* keyAlg, int* curve)
{
    word32 idx = 0;
    word32 algEnd = 0;
    int    ret = 0;
    int    len = 0;
    int    algLen = 0;

    if ((spki == NULL) || (keyAlg == NULL) || (curve == NULL)) {
        return WOLFNANO_E_INVALID_ARG;
    }
    *keyAlg = WN_X509_KEY_UNKNOWN;
    *curve = WN_X509_CURVE_NONE;

    ret = wn_Asn_GetHeader(spki, WN_ASN_SEQ, &idx, &len, spkiLen);
    if (ret >= 0) {
        ret = wn_Asn_GetHeader(spki, WN_ASN_SEQ, &idx, &algLen, spkiLen);
    }
    if (ret >= 0) {
        algEnd = idx + (word32)algLen;
        ret = wn_ParseAlgIdOids(spki, &idx, algEnd, keyAlg, curve);
    }
    return (ret >= 0) ? WOLFNANO_SUCCESS : ret;
}

static int wn_SigAlgFromOid(const byte* p, int len)
{
    int alg = WN_X509_SIG_UNKNOWN;

    if (wn_OidEq(p, len, WN_OID_ECDSA_SHA256, sizeof(WN_OID_ECDSA_SHA256))) {
        alg = WN_X509_SIG_ECDSA_SHA256;
    }
#if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
    else if (wn_OidEq(p, len, WN_OID_ECDSA_SHA384, sizeof(WN_OID_ECDSA_SHA384))) {
        alg = WN_X509_SIG_ECDSA_SHA384;
    }
#endif
#ifndef NO_RSA
    else if (wn_OidEq(p, len, WN_OID_RSA_SHA256, sizeof(WN_OID_RSA_SHA256))) {
        alg = WN_X509_SIG_RSA_SHA256;
    }
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_SHA384)
    else if (wn_OidEq(p, len, WN_OID_RSA_SHA384, sizeof(WN_OID_RSA_SHA384))) {
        alg = WN_X509_SIG_RSA_SHA384;
    }
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_SHA512)
    else if (wn_OidEq(p, len, WN_OID_RSA_SHA512, sizeof(WN_OID_RSA_SHA512))) {
        alg = WN_X509_SIG_RSA_SHA512;
    }
#endif
#ifdef HAVE_ED25519
    else if (wn_OidEq(p, len, WN_OID_ED25519, sizeof(WN_OID_ED25519))) {
        alg = WN_X509_SIG_ED25519;
    }
#endif

    return alg;
}

/* ECDSA and EdDSA signature AlgorithmIdentifiers carry no parameters; RSA-PSS/
 * PKCS#1 carry a DER NULL. Centralized so every sigAlg category test agrees. */
static int wn_SigAlgNoParams(int sigAlg)
{
    return (sigAlg == WN_X509_SIG_ECDSA_SHA256) ||
           (sigAlg == WN_X509_SIG_ECDSA_SHA384) ||
           (sigAlg == WN_X509_SIG_ED25519);
}

static int wn_SigAlgIsRsa(int sigAlg)
{
    return (sigAlg == WN_X509_SIG_RSA_SHA256) ||
           (sigAlg == WN_X509_SIG_RSA_SHA384) ||
           (sigAlg == WN_X509_SIG_RSA_SHA512);
}

#ifndef WOLFNANO_NO_X509_TIME
/* Capture one validity Time as a full TLV (tag+len+value), matching the slice
 * wolfSSL hands to its date parser and self-describing as UTCTime (len 13) or
 * GeneralizedTime (len 15). */
static int wn_GetTime(const byte* der, word32* idx, word32 maxIdx,
                      const byte** out, word16* outLen)
{
    int    ret = 0;
    int    len = 0;
    word32 begin = *idx;
    byte   tag = 0;

    if (*idx >= maxIdx) {
        ret = WOLFNANO_E_X509_DECODE;
    }
    if (ret == 0) {
        tag = der[*idx];
        if ((tag != WN_ASN_UTC_TIME) && (tag != WN_ASN_GEN_TIME)) {
            ret = WOLFNANO_E_X509_DECODE;
        }
    }
    if (ret == 0) {
        ret = wn_Asn_GetHeader(der, tag, idx, &len, maxIdx);
    }
    if (ret >= 0) {
        *out = der + begin;
        *outLen = (word16)((*idx - begin) + (word32)len);
        *idx += (word32)len;
        ret = 0;
    }

    return ret;
}
#endif /* !WOLFNANO_NO_X509_TIME */

#if defined(WOLFNANO_X509_HOSTNAME) && !defined(WOLFNANO_NO_X509_CN)
/* Walk a subject RDNSequence [idx, end) for the commonName attribute value. */
static void wn_FindCN(const byte* der, word32 idx, word32 end,
                      const char** cn, word16* cnLen)
{
    static const byte WN_OID_CN[] = {0x55, 0x04, 0x03};
    int    rdnLen = 0;
    int    atvLen = 0;
    int    oidLen = 0;
    int    valLen = 0;
    word32 rdnEnd;
    word32 atvEnd;
    byte   valTag;

    while ((idx < end) && (*cn == NULL)) {
        if (wn_Asn_GetHeader(der, WN_ASN_SET_OF, &idx, &rdnLen, end) < 0) {
            break;
        }
        rdnEnd = idx + (word32)rdnLen;
        while ((idx < rdnEnd) && (*cn == NULL)) {
            if (wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &atvLen, rdnEnd) < 0) {
                break;
            }
            atvEnd = idx + (word32)atvLen;
            if (wn_Asn_GetHeader(der, WN_ASN_OBJECT_ID, &idx, &oidLen,
                                 atvEnd) < 0) {
                break;
            }
            if (wn_OidEq(der + idx, oidLen, WN_OID_CN, sizeof(WN_OID_CN))) {
                idx += (word32)oidLen;
                if (idx < atvEnd) {
                    valTag = der[idx];
                    /* only accept CN as a text string (UTF8/Printable/T61/IA5),
                     * so a non-string value cannot become a hostname; reject any
                     * embedded NUL (anywhere, not just trailing) so "good.com\0
                     * evil.com" cannot spoof the identity */
                    if (((valTag == WN_ASN_UTF8_STRING) ||
                         (valTag == WN_ASN_PRINTABLE_STRING) ||
                         (valTag == WN_ASN_T61_STRING) ||
                         (valTag == WN_ASN_IA5_STRING)) &&
                        (wn_Asn_GetHeader(der, valTag, &idx, &valLen,
                                          atvEnd) >= 0) &&
                        (valLen >= 1) && (valLen <= WN_X509_MAX_DNS_NAME) &&
                        !wn_HasNul(der + idx, (word32)valLen)) {
                        *cn = (const char*)(der + idx);
                        *cnLen = (word16)valLen;
                    }
                }
            }
            idx = atvEnd;
        }
        idx = rdnEnd;
    }
}
#endif /* WOLFNANO_X509_HOSTNAME && !WOLFNANO_NO_X509_CN */

/* basicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen OPT }. Sets the
 * CA flag; rejects an explicit cA=FALSE (bad DER, per wolfSSL). pathLen ignored. */
static int wn_ExtBasicConstraints(const byte* der, word32 idx, word32 end,
                                  wn_X509Cert* cert, byte crit)
{
    int    rc = 0;
    int    seqLen = 0;
    int    bLen = 0;
    word32 e = 0;

    cert->flags |= WN_X509_F_BC_SET;
    if (crit) {
        cert->flags |= WN_X509_F_BC_CRIT;
    }
    rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &seqLen, end);
    if (rc >= 0) {
        e = idx + (word32)seqLen;
        if (e != end) {                    /* SEQUENCE must fill the extnValue */
            rc = WOLFNANO_E_X509_DECODE;
        }
    }
    if ((rc >= 0) && (idx < e) && (der[idx] == WN_ASN_BOOLEAN)) {
        rc = wn_Asn_GetHeader(der, WN_ASN_BOOLEAN, &idx, &bLen, e);
        if ((rc >= 0) && (bLen != 1)) {
            rc = WOLFNANO_E_X509_DECODE;   /* DER BOOLEAN is exactly one octet */
        }
        if (rc >= 0) {
            if (der[idx] == 0xFF) {
                cert->flags |= WN_X509_F_CA;
            }
            else {
                /* TRUE must be 0xFF; an explicit FALSE violates the DEFAULT */
                rc = WOLFNANO_E_X509_DECODE;
            }
            idx += (word32)bLen;           /* past the cA value */
        }
    }
#ifndef WOLFNANO_NO_X509_PATHLEN
    if ((rc >= 0) && (idx < e)) {
        /* only an optional pathLenConstraint INTEGER may follow (value not
         * enforced); it must fill the SEQUENCE - reject other trailing DER */
        rc = wn_Asn_GetHeader(der, WN_ASN_INTEGER, &idx, &bLen, e);
        if (rc >= 0) {
            idx += (word32)bLen;
        }
    }
#endif
    if ((rc >= 0) && (idx != e)) {
        rc = WOLFNANO_E_X509_DECODE;
    }

    return (rc >= 0) ? 0 : rc;
}

/* keyUsage: BIT STRING decoded little-endian into the wolfSSL KEYUSE_* layout. */
static int wn_ExtKeyUsage(const byte* der, word32 idx, word32 end,
                          wn_X509Cert* cert, byte crit)
{
    int rc = 0;
    int kuLen = 0;

    cert->flags |= WN_X509_F_KU_SET;
    if (crit) {
        cert->flags |= WN_X509_F_KU_CRIT;
    }
    /* the BIT STRING must fill the extnValue exactly (no trailing bytes) */
    rc = wn_Asn_GetHeaderExact(der, WN_ASN_BIT_STRING, &idx, &kuLen, end);
    if ((rc >= 0) && ((kuLen < 1) || (der[idx] > 7))) {
        rc = WOLFNANO_E_X509_DECODE;        /* unused-bits count is 0..7 */
    }
    if ((rc >= 0) && (kuLen >= 2) &&
        ((der[idx + kuLen - 1] & (byte)((1u << der[idx]) - 1u)) != 0)) {
        rc = WOLFNANO_E_X509_DECODE;        /* DER: unused padding bits must be 0 */
    }
    if (rc >= 0) {
        if (kuLen >= 2) {                   /* [unused-bits octet][byte0]... */
            cert->keyUsage = der[idx + 1];
        }
        if (kuLen >= 3) {
            cert->keyUsage |= (word16)((word16)der[idx + 2] << 8);
        }
        if (cert->keyUsage == 0) {          /* RFC 5280 4.2.1.3: >= 1 bit set */
            rc = WOLFNANO_E_X509_DECODE;
        }
    }

    return (rc >= 0) ? 0 : rc;
}

/* extKeyUsage: SEQUENCE OF KeyPurposeId; OR in serverAuth, skip unknown OIDs. */
static int wn_ExtExtKeyUsage(const byte* der, word32 idx, word32 end,
                             wn_X509Cert* cert, byte crit)
{
    int    rc = 0;
    int    seqLen = 0;
    int    oidLen = 0;
    word32 e = 0;

    cert->flags |= WN_X509_F_EKU_SET;
    if (crit) {
        cert->flags |= WN_X509_F_EKU_CRIT;
    }
    rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &seqLen, end);
    if (rc >= 0) {
        e = idx + (word32)seqLen;
        if (e != end) {                    /* SEQUENCE must fill the extnValue */
            rc = WOLFNANO_E_X509_DECODE;
        }
        else if (seqLen == 0) {            /* RFC 5280 4.2.1.12: >= 1 KeyPurposeId */
            rc = WOLFNANO_E_X509_DECODE;
        }
        while ((rc >= 0) && (idx < e)) {
            rc = wn_Asn_GetHeader(der, WN_ASN_OBJECT_ID, &idx, &oidLen, e);
            if (rc >= 0) {
                if (wn_OidEq(der + idx, oidLen, WN_OID_EKU_SRVAUTH,
                             sizeof(WN_OID_EKU_SRVAUTH))) {
                    cert->extKeyUsage |= WN_EXTKEYUSE_SERVER_AUTH;
                }
                else if (wn_OidEq(der + idx, oidLen, WN_OID_EKU_ANY,
                                  sizeof(WN_OID_EKU_ANY))) {
                    cert->extKeyUsage |= WN_EXTKEYUSE_ANY;
                }
                idx += (word32)oidLen;
            }
        }
    }

    return (rc >= 0) ? 0 : rc;
}

#ifdef WOLFNANO_X509_HOSTNAME
/* subjectAltName: SEQUENCE OF GeneralName; collect dNSName ([2]) into san[].
 * Other name forms are ignored; pool overflow fails closed. */
static int wn_ExtAltName(const byte* der, word32 idx, word32 end,
                         wn_X509Cert* cert, byte crit)
{
    int    rc = 0;
    int    seqLen = 0;
    int    nameLen = 0;
    word32 e = 0;
    byte   tag;

    cert->flags |= WN_X509_F_SAN_SET;
    if (crit) {
        cert->flags |= WN_X509_F_SAN_CRIT;
    }
    rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &seqLen, end);
    if (rc >= 0) {
        e = idx + (word32)seqLen;
        if (e != end) {                    /* SEQUENCE must fill the extnValue */
            rc = WOLFNANO_E_X509_DECODE;
        }
        else if (seqLen == 0) {            /* RFC 5280 4.2.1.6: >= 1 GeneralName */
            rc = WOLFNANO_E_X509_DECODE;
        }
        while ((rc >= 0) && (idx < e)) {
            tag = der[idx];
            rc = wn_Asn_GetHeader(der, tag, &idx, &nameLen, e);
            if (rc >= 0) {
                if (tag == WN_ASN_SAN_DNS) {
                    /* Reject an embedded NUL in dNSName: it enables
                     * "good.com\0evil.com" identity spoofing (wolfSSL parity).
                     * Oversized names cannot be a valid host and would narrow
                     * to word16, so reject them too. */
                    if ((nameLen < 1) || (nameLen > WN_X509_MAX_DNS_NAME) ||
                        wn_HasNul(der + idx, (word32)nameLen)) {
                        rc = WOLFNANO_E_X509_DECODE;
                    }
                    else if (cert->sanCount < WN_X509_MAX_SAN) {
                        cert->san[cert->sanCount].name = (const char*)(der + idx);
                        cert->san[cert->sanCount].len = (word16)nameLen;
                        cert->sanCount++;
                    }
                    /* pool full: keep parsing so the cert stays usable for the
                     * names that fit; a target beyond the pool simply fails to
                     * match, and WN_X509_F_SAN_SET blocks an unsafe CN fallback */
                }
                idx += (word32)nameLen;
            }
        }
    }

    return (rc >= 0) ? 0 : rc;
}
#endif /* WOLFNANO_X509_HOSTNAME */

/* Walk the v3 extensions ([3] EXPLICIT SEQUENCE OF Extension) inside the
 * tbsCertificate. Each Extension is SEQUENCE { extnID OID, critical BOOLEAN
 * DEFAULT FALSE, extnValue OCTET STRING }. Recognized OIDs are tracked for
 * duplicate rejection; an unrecognized critical extension fails closed. */
static int wn_ParseExtensions(const byte* der, word32 idx, word32 tbsEnd,
                              wn_X509Cert* cert, int version)
{
    int    rc = 0;
    int    len = 0;
    int    oidLen = 0;
    int    valLen = 0;
    int    bLen = 0;
    word32 extEnd = 0;
    word32 exEnd = 0;
    word32 ctx3End = 0;
    word32 oidAt = 0;
    word16 seen = 0;
    byte   crit;

    /* Skip optional issuerUniqueID [1] / subjectUniqueID [2] (primitive IMPLICIT
     * BIT STRINGs, tags 0x81/0x82); find [3] extensions. Any other tag between
     * the SPKI and extensions is malformed: fail closed. RFC 5280 4.1.2.1:
     * unique IDs require v2+, extensions require v3. */
    while ((rc >= 0) && (idx < tbsEnd)) {
        if (der[idx] == WN_ASN_CTX3) {
            break;
        }
        if (((der[idx] != WN_ASN_UID1) && (der[idx] != WN_ASN_UID2)) ||
            (version < 1)) {
            rc = WOLFNANO_E_X509_DECODE;
            break;
        }
        rc = wn_Asn_GetHeader(der, der[idx], &idx, &len, tbsEnd);
        if (rc >= 0) {
            idx += (word32)len;
        }
    }

    if ((rc >= 0) && (idx < tbsEnd) && (version != 2)) {
        rc = WOLFNANO_E_X509_DECODE;        /* extensions present but not v3 */
    }
    if ((rc >= 0) && (idx < tbsEnd)) {
        rc = wn_Asn_GetHeader(der, WN_ASN_CTX3, &idx, &len, tbsEnd);
        if (rc >= 0) {
            ctx3End = idx + (word32)len;
            if (ctx3End != tbsEnd) {        /* [3] is the last tbsCertificate field */
                rc = WOLFNANO_E_X509_DECODE;
            }
        }
        if (rc >= 0) {
            rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &len, ctx3End);
        }
        if (rc >= 0) {
            extEnd = idx + (word32)len;
            if (extEnd != ctx3End) {        /* SEQUENCE fills the [3] wrapper */
                rc = WOLFNANO_E_X509_DECODE;
            }
            else if (len == 0) {            /* RFC 5280 4.1.2.9: >= 1 extension */
                rc = WOLFNANO_E_X509_DECODE;
            }
        }
        while ((rc >= 0) && (idx < extEnd)) {
            crit = 0;
            rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &len, extEnd);
            if (rc < 0) {
                break;
            }
            exEnd = idx + (word32)len;
            rc = wn_Asn_GetHeader(der, WN_ASN_OBJECT_ID, &idx, &oidLen, exEnd);
            if (rc < 0) {
                break;
            }
            oidAt = idx;
            idx += (word32)oidLen;
            if ((idx < exEnd) && (der[idx] == WN_ASN_BOOLEAN)) {
                rc = wn_Asn_GetHeader(der, WN_ASN_BOOLEAN, &idx, &bLen, exEnd);
                if (rc < 0) {
                    break;
                }
                if (bLen != 1) {           /* DER BOOLEAN is exactly one octet */
                    rc = WOLFNANO_E_X509_DECODE;
                    break;
                }
                if (der[idx] != 0xFF) {    /* DER TRUE is 0xFF; FALSE is omitted */
                    rc = WOLFNANO_E_X509_DECODE;
                    break;
                }
                crit = 1;
                idx += (word32)bLen;
            }
            rc = wn_Asn_GetHeader(der, WN_ASN_OCTET_STRING, &idx, &valLen, exEnd);
            if (rc < 0) {
                break;
            }
            if ((idx + (word32)valLen) != exEnd) {
                rc = WOLFNANO_E_X509_DECODE;   /* extnValue must end the Extension */
                break;
            }
            if (wn_OidEq(der + oidAt, oidLen, WN_OID_EXT_BC, sizeof(WN_OID_EXT_BC))) {
                if (seen & WN_EXT_SEEN_BC) {
                    rc = WOLFNANO_E_X509_DECODE;
                }
                else {
                    seen |= WN_EXT_SEEN_BC;
                    rc = wn_ExtBasicConstraints(der, idx, idx + (word32)valLen,
                                                cert, crit);
                }
            }
            else if (wn_OidEq(der + oidAt, oidLen, WN_OID_EXT_KU,
                              sizeof(WN_OID_EXT_KU))) {
                if (seen & WN_EXT_SEEN_KU) {
                    rc = WOLFNANO_E_X509_DECODE;
                }
                else {
                    seen |= WN_EXT_SEEN_KU;
                    rc = wn_ExtKeyUsage(der, idx, idx + (word32)valLen, cert,
                                        crit);
                }
            }
            else if (wn_OidEq(der + oidAt, oidLen, WN_OID_EXT_EKU,
                              sizeof(WN_OID_EXT_EKU))) {
                if (seen & WN_EXT_SEEN_EKU) {
                    rc = WOLFNANO_E_X509_DECODE;
                }
                else {
                    seen |= WN_EXT_SEEN_EKU;
                    rc = wn_ExtExtKeyUsage(der, idx, idx + (word32)valLen, cert,
                                           crit);
                }
            }
            else if (wn_OidEq(der + oidAt, oidLen, WN_OID_EXT_SAN,
                              sizeof(WN_OID_EXT_SAN))) {
                if (seen & WN_EXT_SEEN_SAN) {
                    rc = WOLFNANO_E_X509_DECODE;
                }
                else {
                    seen |= WN_EXT_SEEN_SAN;
#ifdef WOLFNANO_X509_HOSTNAME
                    rc = wn_ExtAltName(der, idx, idx + (word32)valLen, cert,
                                       crit);
#endif
                    /* HOSTNAME off: SAN is recognized (so a critical SAN is not
                     * an unknown-critical failure) but not stored; a pin-only
                     * build authenticates by key pin, not name. */
                }
            }
            else if (crit) {
                rc = WOLFNANO_E_X509_CRITEXT;
            }
            idx = exEnd;
        }
    }

    return rc;
}

int wn_X509_Parse(wn_X509Cert* cert, const byte* der, word32 derLen)
{
    int    rc = 0;
    word32 idx = 0;
    word32 maxIdx = 0;
    word32 certEnd = 0;
    word32 certBegin = 0;
    word32 tbsEnd = 0;
    word32 spkiBegin = 0;
    word32 spkiEnd = 0;
    word32 algEnd = 0;
    word32 innerBegin = 0;
    word32 outerBegin = 0;
    word32 valEnd = 0;
    word32 verEnd = 0;
    word32 oidIdx = 0;
    const byte* innerPtr = NULL;
    word32 innerLen = 0;
    int    totLen = 0;
    int    certLen = 0;
    int    len = 0;
    int    oidLen = 0;
    int    algLen = 0;
    int    version = 0;

    if ((cert == NULL) || (der == NULL) || (derLen < 2) ||
        (derLen > 0x7FFFFFFF)) {
        rc = WOLFNANO_E_INVALID_ARG;
    }

    /* Certificate ::= SEQUENCE */
    if (rc == 0) {
        XMEMSET(cert, 0, sizeof(*cert));
        maxIdx = derLen;
        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &totLen, maxIdx);
    }
    if (rc >= 0) {
        /* single DER cert: reject trailing bytes after the Certificate SEQUENCE */
        certEnd = idx + (word32)totLen;
        if (certEnd != derLen) {
            rc = WOLFNANO_E_X509_DECODE;
        }
    }

    /* tbsCertificate ::= SEQUENCE (the hash range) */
    if (rc >= 0) {
        certBegin = idx;
        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &certLen, maxIdx);
    }
    if (rc >= 0) {
        cert->tbs = der + certBegin;
        cert->tbsLen = (word32)certLen + (idx - certBegin);
        tbsEnd = certBegin + cert->tbsLen;  /* bound every TBS child to the TBS */
    }
    if ((rc >= 0) && (idx < tbsEnd) && (der[idx] == WN_ASN_CTX0)) {
        /* version [0] EXPLICIT { INTEGER }; absent => v1 DEFAULT (version = 0) */
        rc = wn_Asn_GetHeader(der, WN_ASN_CTX0, &idx, &len, tbsEnd);
        if (rc >= 0) {
            verEnd = idx + (word32)len;
            rc = wn_Asn_GetHeader(der, WN_ASN_INTEGER, &idx, &len, verEnd);
        }
        if (rc >= 0) {
            /* when present, a single-octet v2/v3 filling [0] exactly; explicit
             * v1 (value 0) violates the DEFAULT and must be omitted instead */
            if ((len != 1) || (der[idx] < 1) || (der[idx] > 2) ||
                ((idx + 1u) != verEnd)) {
                rc = WOLFNANO_E_X509_DECODE;
            }
            else {
                version = der[idx];         /* 1=v2, 2=v3 */
            }
        }
        if (rc >= 0) {
            idx = verEnd;                   /* past version */
        }
    }
    if (rc >= 0) {
        rc = wn_Asn_GetHeader(der, WN_ASN_INTEGER, &idx, &len, tbsEnd); /* serial */
    }
    if ((rc >= 0) && (len < 1)) {
        rc = WOLFNANO_E_X509_DECODE;        /* RFC 5280: serialNumber >= 1 byte */
    }
    if (rc >= 0) {
        idx += (word32)len;                 /* skip serialNumber */

        /* tbsCertificate.signature AlgId (inner; must equal outer) */
        innerBegin = idx;
        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &len, tbsEnd);
    }
    if (rc >= 0) {
        innerPtr = der + innerBegin;
        innerLen = (word32)len + (idx - innerBegin);
        idx += (word32)len;                 /* skip inner signature AlgId */

        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &len, tbsEnd);
    }
    if (rc >= 0) {
        idx += (word32)len;                 /* skip issuer */

        /* validity ::= SEQUENCE { notBefore Time, notAfter Time } */
        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &len, tbsEnd);
    }
    if (rc >= 0) {
        valEnd = idx + (word32)len;
#ifndef WOLFNANO_NO_X509_TIME
        rc = wn_GetTime(der, &idx, valEnd, &cert->notBefore,
                        &cert->notBeforeLen);
        if (rc == 0) {
            rc = wn_GetTime(der, &idx, valEnd, &cert->notAfter,
                            &cert->notAfterLen);
        }
        if ((rc == 0) && (idx != valEnd)) {
            rc = WOLFNANO_E_X509_DECODE;    /* validity holds exactly two Times */
        }
#endif
    }
    if (rc >= 0) {
        idx = valEnd;                       /* skip to end of validity */

        /* subject ::= RDNSequence */
        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &len, tbsEnd);
    }
    if (rc >= 0) {
#if defined(WOLFNANO_X509_HOSTNAME) && !defined(WOLFNANO_NO_X509_CN)
        wn_FindCN(der, idx, idx + (word32)len, &cert->subjectCN,
                  &cert->subjectCNLen);
#endif
        idx += (word32)len;                 /* skip subject */

        /* subjectPublicKeyInfo ::= SEQUENCE */
        spkiBegin = idx;
        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &len, tbsEnd);
    }
    if (rc >= 0) {
        cert->spki = der + spkiBegin;
        cert->spkiLen = (word32)len + (idx - spkiBegin);
        spkiEnd = idx + (word32)len;        /* bound SPKI children to the SPKI */

        /* AlgorithmIdentifier ::= SEQUENCE { OID, params } */
        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &algLen, spkiEnd);
    }
    if (rc >= 0) {
        algEnd = idx + (word32)algLen;
        rc = wn_ParseAlgIdOids(der, &idx, algEnd, &cert->keyAlg, &cert->curve);
    }
    if (rc >= 0) {
        idx = algEnd;                       /* skip to subjectPublicKey */
        rc = wn_Asn_GetBitString(der, &idx, spkiEnd, &cert->pubKey,
                                 &cert->pubKeyLen);
    }
    if ((rc >= 0) && (idx != spkiEnd)) {    /* SPKI must be consumed exactly */
        rc = WOLFNANO_E_X509_DECODE;
    }
    if (rc >= 0) {
        /* v3 extensions ([3] EXPLICIT) before the end of the tbsCertificate */
        rc = wn_ParseExtensions(der, idx, certBegin + cert->tbsLen, cert,
                                version);
    }
    if (rc >= 0) {
        /* Certificate.signatureAlgorithm (outer) after the tbsCertificate */
        idx = certBegin + cert->tbsLen;
        outerBegin = idx;
        rc = wn_Asn_GetHeader(der, WN_ASN_SEQ, &idx, &len, maxIdx);
    }
    if (rc >= 0) {
        oidIdx = idx;
        /* bound the OID to the signatureAlgorithm SEQUENCE, not the whole cert */
        rc = wn_Asn_GetHeader(der, WN_ASN_OBJECT_ID, &oidIdx, &oidLen,
                              idx + (word32)len);
    }
    if (rc >= 0) {
        cert->sigAlg = wn_SigAlgFromOid(der + oidIdx, oidLen);

        /* RFC 5280 4.1.1.2: inner and outer signatureAlgorithm MUST match. */
        if (((word32)len + (idx - outerBegin) != innerLen) ||
            !wn_MemEq(innerPtr, der + outerBegin, innerLen)) {
            rc = WOLFNANO_E_X509_DECODE;
        }
    }
    if (rc >= 0) {
        /* signatureAlgorithm parameter shape: ECDSA/EdDSA carry no parameters
         * (AlgId ends at the OID); RSA carries DER NULL (asn.c IsSigAlgoNoParams
         * and PKCS#1). */
        if (wn_SigAlgNoParams(cert->sigAlg)) {
            if ((oidIdx + (word32)oidLen) != (idx + (word32)len)) {
                rc = WOLFNANO_E_X509_DECODE;
            }
        }
        else if (wn_SigAlgIsRsa(cert->sigAlg)) {
            if (((oidIdx + (word32)oidLen + 2) != (idx + (word32)len)) ||
                (der[oidIdx + (word32)oidLen] != WN_ASN_NULL) ||
                (der[oidIdx + (word32)oidLen + 1] != 0x00)) {
                rc = WOLFNANO_E_X509_DECODE;
            }
        }
    }
    if (rc >= 0) {
        idx += (word32)len;                 /* skip outer signatureAlgorithm */
        rc = wn_Asn_GetBitString(der, &idx, maxIdx, &cert->sig, &cert->sigLen);
    }
    /* signatureValue must be the last child: no extra data inside the
     * Certificate SEQUENCE after it */
    if ((rc >= 0) && (idx != certEnd)) {
        rc = WOLFNANO_E_X509_DECODE;
    }

    if ((rc < 0) && (cert != NULL)) {
        XMEMSET(cert, 0, sizeof(*cert));    /* fields valid only on success */
    }
    return (rc >= 0) ? WOLFNANO_SUCCESS : rc;
}

#ifdef WOLFNANO_X509
static int wn_HashForSig(int sigAlg)
{
    int h = WC_HASH_TYPE_NONE;

    switch (sigAlg) {
        case WN_X509_SIG_ECDSA_SHA256:
        case WN_X509_SIG_RSA_SHA256:
            h = WC_HASH_TYPE_SHA256;
            break;
#if defined(HAVE_ECC384) && defined(WOLFSSL_SHA384)
        case WN_X509_SIG_ECDSA_SHA384:
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_SHA384)
        case WN_X509_SIG_RSA_SHA384:
#endif
#if defined(WOLFSSL_SHA384) && (defined(HAVE_ECC384) || !defined(NO_RSA))
            h = WC_HASH_TYPE_SHA384;
            break;
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_SHA512)
        case WN_X509_SIG_RSA_SHA512:
            h = WC_HASH_TYPE_SHA512;
            break;
#endif
        default: /* LCOV_EXCL_LINE: unreachable; guarded earlier by wn_SigAlgMatchesKey */
            break;                          /* Ed25519: signs the message */ /* LCOV_EXCL_LINE: unreachable; guarded earlier by wn_SigAlgMatchesKey */
    }
    return h;
}

#ifdef HAVE_ECC
static int wn_CurveId(int curve)
{
    int id = ECC_CURVE_INVALID;

    switch (curve) {
        case WN_X509_CURVE_P256: id = ECC_SECP256R1; break;
#ifdef HAVE_ECC384
        case WN_X509_CURVE_P384: id = ECC_SECP384R1; break;
#endif
        default: break;
    }
    return id;
}

static int wn_VerifyEcdsa(const wn_X509Cert* child, const wn_X509Cert* issuer)
{
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* key = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL,
                                     DYNAMIC_TYPE_TMP_BUFFER);
#else
    ecc_key key[1];
#endif
    byte    hash[WC_MAX_DIGEST_SIZE];
    int     ret = WOLFNANO_SUCCESS;
    int     hashType = wn_HashForSig(child->sigAlg);
    int     curveId = wn_CurveId(issuer->curve);
    int     hashLen = wc_HashGetDigestSize((enum wc_HashType)hashType);
    int     res = 0, keyInit = 0;

#ifdef WOLFSSL_SMALL_STACK
    if (key == NULL) {
        ret = WOLFNANO_E_CRYPTO;
    }
#endif
    if ((ret == WOLFNANO_SUCCESS) &&
        ((curveId == ECC_CURVE_INVALID) || (hashLen <= 0))) {
        ret = WOLFNANO_E_BAD_CERT;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_Hash((enum wc_HashType)hashType, child->tbs, child->tbsLen, hash,
                 (word32)hashLen) != 0)) {
        ret = WOLFNANO_E_CRYPTO; /* LCOV_EXCL_LINE: wc_* init/hash cannot fail on validated input (FIPS/hw only) */
    }
    if ((ret == WOLFNANO_SUCCESS) && (wc_ecc_init(key) != 0)) {
        ret = WOLFNANO_E_CRYPTO; /* LCOV_EXCL_LINE: wc_* init/hash cannot fail on validated input (FIPS/hw only) */
    }
    else if (ret == WOLFNANO_SUCCESS) {
        keyInit = 1;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_ecc_import_x963_ex(issuer->pubKey, issuer->pubKeyLen, key,
                               curveId) != 0)) {
        ret = WOLFNANO_E_BAD_CERT;
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_ecc_verify_hash(child->sig, child->sigLen, hash,
                (word32)hashLen, &res, key) != 0) || (res != 1)) {
            ret = WOLFNANO_E_BAD_CERT;
        }
    }
    if (keyInit) {
        wc_ecc_free(key);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}
#endif /* HAVE_ECC */

#ifndef NO_RSA
/* Split a raw RSAPublicKey (SEQUENCE { n INTEGER, e INTEGER }) into n/e refs.
 * WOLFNANO_LOCAL: also used by the CertificateVerify raw-import path. */
WOLFNANO_LOCAL int wn_X509_RsaRawNE(const byte* in, word32 inLen, const byte** n,
                                    word32* nLen, const byte** e, word32* eLen)
{
    word32 idx = 0;
    word32 seqEnd = 0;
    int    ret = WOLFNANO_SUCCESS;
    int    len = 0;

    if ((in == NULL) || (n == NULL) || (nLen == NULL) || (e == NULL) ||
        (eLen == NULL)) {
        return WOLFNANO_E_INVALID_ARG;
    }
    if (wn_Asn_GetHeader(in, WN_ASN_SEQ, &idx, &len, inLen) < 0) {
        ret = WOLFNANO_E_X509_DECODE;
    }
    else {
        seqEnd = idx + (word32)len;
        if (seqEnd != inLen) {              /* RSAPublicKey must fill the BIT STRING */
            ret = WOLFNANO_E_X509_DECODE;
        }
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wn_Asn_GetHeader(in, WN_ASN_INTEGER, &idx, &len, seqEnd) < 0)) {
        ret = WOLFNANO_E_X509_DECODE;
    }
    if ((ret == WOLFNANO_SUCCESS) && ((len < 1) || ((in[idx] & 0x80) != 0))) {
        ret = WOLFNANO_E_X509_DECODE;       /* modulus must be a positive INTEGER */
    }
    if (ret == WOLFNANO_SUCCESS) {
        *n = in + idx;
        *nLen = (word32)len;
        idx += (word32)len;
        if (wn_Asn_GetHeader(in, WN_ASN_INTEGER, &idx, &len, seqEnd) < 0) {
            ret = WOLFNANO_E_X509_DECODE;
        }
    }
    if ((ret == WOLFNANO_SUCCESS) && ((len < 1) || ((in[idx] & 0x80) != 0))) {
        ret = WOLFNANO_E_X509_DECODE;       /* exponent must be a positive INTEGER */
    }
    if (ret == WOLFNANO_SUCCESS) {
        *e = in + idx;
        *eLen = (word32)len;
        idx += (word32)len;
        if (idx != seqEnd) {                /* RSAPublicKey consumed exactly */
            ret = WOLFNANO_E_X509_DECODE;
        }
    }
    return ret;
}

static int wn_VerifyRsa(const wn_X509Cert* child, const wn_X509Cert* issuer)
{
#ifdef WOLFSSL_SMALL_STACK
    RsaKey*     key = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
#else
    RsaKey      key[1];
#endif
    byte        hash[WC_MAX_DIGEST_SIZE];
    byte        encoded[128];               /* DigestInfo(hash): <= ~83 bytes */
    byte        decoded[512];               /* recovered block, up to RSA-4096 */
    const byte* n = NULL;
    const byte* e = NULL;
    word32      nLen = 0, eLen = 0;
    word32      encSz = 0;
    int         ret = WOLFNANO_SUCCESS;
    int         hashType = wn_HashForSig(child->sigAlg);
    int         hashLen = wc_HashGetDigestSize((enum wc_HashType)hashType);
    int         hashOID = wc_HashGetOID((enum wc_HashType)hashType);
    int         keyInit = 0, verSz = 0;

#ifdef WOLFSSL_SMALL_STACK
    if (key == NULL) {
        ret = WOLFNANO_E_CRYPTO;
    }
#endif
    if ((ret == WOLFNANO_SUCCESS) && ((hashLen <= 0) || (hashOID <= 0))) {
        ret = WOLFNANO_E_BAD_CERT; /* LCOV_EXCL_LINE: unreachable; guarded earlier by wn_SigAlgMatchesKey */
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_X509_RsaRawNE(issuer->pubKey, issuer->pubKeyLen, &n, &nLen,
                            &e, &eLen);
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_Hash((enum wc_HashType)hashType, child->tbs, child->tbsLen, hash,
                 (word32)hashLen) != 0)) {
        ret = WOLFNANO_E_CRYPTO; /* LCOV_EXCL_LINE: wc_* init/hash cannot fail on validated input (FIPS/hw only) */
    }
    if ((ret == WOLFNANO_SUCCESS) && (wc_InitRsaKey(key, NULL) != 0)) {
        ret = WOLFNANO_E_CRYPTO; /* LCOV_EXCL_LINE: wc_* init/hash cannot fail on validated input (FIPS/hw only) */
    }
    else if (ret == WOLFNANO_SUCCESS) {
        keyInit = 1;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_RsaPublicKeyDecodeRaw(n, nLen, e, eLen, key) != 0)) {
        ret = WOLFNANO_E_BAD_CERT;
    }
    /* PKCS#1 v1.5: recover the block and compare to the expected DigestInfo
     * (the check wolfSSL's RSA path does internally; avoids the sig wrapper). */
    if (ret == WOLFNANO_SUCCESS) {
        encSz = wc_EncodeSignature(encoded, hash, (word32)hashLen, hashOID);
        verSz = wc_RsaSSL_Verify(child->sig, child->sigLen, decoded,
                                 (word32)sizeof(decoded), key);
        if ((verSz < 0) || ((word32)verSz != encSz) ||
            !wn_MemEq(decoded, encoded, encSz)) {
            ret = WOLFNANO_E_BAD_CERT;
        }
    }
    if (keyInit) {
        wc_FreeRsaKey(key);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_ED25519
static int wn_VerifyEd25519(const wn_X509Cert* child, const wn_X509Cert* issuer)
{
#ifdef WOLFSSL_SMALL_STACK
    ed25519_key* key = (ed25519_key*)XMALLOC(sizeof(ed25519_key), NULL,
                                             DYNAMIC_TYPE_TMP_BUFFER);
#else
    ed25519_key key[1];
#endif
    int ret = WOLFNANO_SUCCESS;
    int res = 0, keyInit = 0;

#ifdef WOLFSSL_SMALL_STACK
    if (key == NULL) {
        ret = WOLFNANO_E_CRYPTO;
    }
#endif
    if ((ret == WOLFNANO_SUCCESS) && (wc_ed25519_init(key) != 0)) {
        ret = WOLFNANO_E_CRYPTO; /* LCOV_EXCL_LINE: wc_* init/hash cannot fail on validated input (FIPS/hw only) */
    }
    else if (ret == WOLFNANO_SUCCESS) {
        keyInit = 1;
    }
    if ((ret == WOLFNANO_SUCCESS) &&
        (wc_ed25519_import_public(issuer->pubKey, issuer->pubKeyLen, key)
            != 0)) {
        ret = WOLFNANO_E_BAD_CERT;
    }
    if (ret == WOLFNANO_SUCCESS) {
        if ((wc_ed25519_verify_msg(child->sig, child->sigLen, child->tbs,
                child->tbsLen, &res, key) != 0) || (res != 1)) {
            ret = WOLFNANO_E_BAD_CERT;
        }
    }
    if (keyInit) {
        wc_ed25519_free(key);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}
#endif /* HAVE_ED25519 */

/* The child's signatureAlgorithm must name an algorithm consistent with the
 * issuer key type; otherwise an ECDSA key could verify a TBS whose OID claims
 * RSA (same hash). Add a case here when adding a new signature algorithm. */
static int wn_SigAlgMatchesKey(int keyAlg, int sigAlg)
{
    int ok = 0;

    switch (keyAlg) {
        case WN_X509_KEY_ECDSA:
            ok = (sigAlg == WN_X509_SIG_ECDSA_SHA256) ||
                 (sigAlg == WN_X509_SIG_ECDSA_SHA384);
            break;
        case WN_X509_KEY_RSA:
            ok = wn_SigAlgIsRsa(sigAlg);
            break;
        case WN_X509_KEY_ED25519:
            ok = (sigAlg == WN_X509_SIG_ED25519);
            break;
        default:
            ok = 0;
            break;
    }
    return ok;
}

int wn_X509_VerifySignedBy(const wn_X509Cert* child, const wn_X509Cert* issuer)
{
    int ret = WOLFNANO_SUCCESS;

    if ((child == NULL) || (issuer == NULL) || (child->tbs == NULL) ||
        (child->sig == NULL) || (issuer->pubKey == NULL)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    else if (!wn_SigAlgMatchesKey(issuer->keyAlg, child->sigAlg)) {
        ret = WOLFNANO_E_BAD_CERT;
    }
    else {
        switch (issuer->keyAlg) {
#ifdef HAVE_ECC
            case WN_X509_KEY_ECDSA:
                ret = wn_VerifyEcdsa(child, issuer);
                break;
#endif
#ifndef NO_RSA
            case WN_X509_KEY_RSA:
                ret = wn_VerifyRsa(child, issuer);
                break;
#endif
#ifdef HAVE_ED25519
            case WN_X509_KEY_ED25519:
                ret = wn_VerifyEd25519(child, issuer);
                break;
#endif
            default: /* LCOV_EXCL_LINE: unreachable; guarded earlier by wn_SigAlgMatchesKey */
                ret = WOLFNANO_E_UNSUPPORTED; /* LCOV_EXCL_LINE: unreachable; guarded earlier by wn_SigAlgMatchesKey */
                break; /* LCOV_EXCL_LINE: unreachable; guarded earlier by wn_SigAlgMatchesKey */
        }
    }
    return ret;
}
#else /* !WOLFNANO_X509 */
int wn_X509_VerifySignedBy(const wn_X509Cert* child, const wn_X509Cert* issuer)
{
    (void)child;
    (void)issuer;
    return WOLFNANO_E_UNSUPPORTED;
}
#endif /* WOLFNANO_X509 */

#ifndef WOLFNANO_NO_X509_TIME
/* Days since the Unix epoch for a proleptic-Gregorian UTC date (RFC 5280
 * 4.1.2.5). Standard civil-date math, no allocation, no platform time calls. */
static long wn_DaysFromCivil(int y, int m, int d)
{
    long era;
    unsigned yoe;
    unsigned doy;
    unsigned doe;

    if (m <= 2) {
        y -= 1;
    }
    era = (long)((y >= 0 ? y : y - 399) / 400);
    yoe = (unsigned)(y - era * 400);
    doy = (unsigned)((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1);
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097L + (long)doe - 719468L;
}

static int wn_DaysInMonth(int y, int m)
{
    static const int mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
    int leap = ((y % 4) == 0) && (((y % 100) != 0) || ((y % 400) == 0));

    return ((m == 2) && leap) ? 29 : mdays[m - 1];
}

static int wn_Dig2(const byte* p, int* out)
{
    int ret = WOLFNANO_E_X509_DECODE;

    if ((p[0] >= '0') && (p[0] <= '9') && (p[1] >= '0') && (p[1] <= '9')) {
        *out = (p[0] - '0') * 10 + (p[1] - '0');
        ret = WOLFNANO_SUCCESS;
    }
    return ret;
}

/* Parse a validity Time TLV into Unix-epoch seconds. On success writes *epoch
 * (negative for valid pre-1970 dates); status is separate from the value. */
static int wn_CertTimeEpoch(const byte* tlv, word16 tlvLen, long long* epoch)
{
    const byte* p = NULL;
    int         ret = WOLFNANO_SUCCESS;
    int         y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    int         contentLen;
#ifndef WOLFNANO_NO_X509_GENTIME
    int         c = 0;
#endif

    if ((tlv == NULL) || (epoch == NULL) || (tlvLen < 2) ||
        ((int)tlv[1] + 2 != (int)tlvLen)) {
        ret = WOLFNANO_E_X509_DECODE;
    }
    if (ret == WOLFNANO_SUCCESS) {
        contentLen = tlv[1];
        p = tlv + 2;
        if ((tlv[0] == WN_ASN_UTC_TIME) && (contentLen == 13)) {
            ret = wn_Dig2(p, &y);
            y += (y < 50) ? 2000 : 1900;    /* RFC 5280 4.1.2.5.1 pivot */
            p += 2;
        }
#ifndef WOLFNANO_NO_X509_GENTIME
        else if ((tlv[0] == WN_ASN_GEN_TIME) && (contentLen == 15)) {
            ret = wn_Dig2(p, &c);
            if (ret == WOLFNANO_SUCCESS) {
                ret = wn_Dig2(p + 2, &y);
            }
            y += c * 100;
            p += 4;
        }
#endif
        else {
            ret = WOLFNANO_E_X509_DECODE;
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Dig2(p, &mo);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Dig2(p + 2, &d);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Dig2(p + 4, &h);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Dig2(p + 6, &mi);
    }
    if (ret == WOLFNANO_SUCCESS) {
        ret = wn_Dig2(p + 8, &s);
    }
    if ((ret == WOLFNANO_SUCCESS) && (p[10] != 'Z')) {
        ret = WOLFNANO_E_X509_DECODE;       /* RFC 5280: UTC, 'Z'-terminated */
    }
    if ((ret == WOLFNANO_SUCCESS) && ((mo < 1) || (mo > 12) || (d < 1) ||
            (d > wn_DaysInMonth(y, mo)) || (h > 23) || (mi > 59) || (s > 60))) {
        ret = WOLFNANO_E_X509_DECODE;
    }
    if (ret == WOLFNANO_SUCCESS) {
        *epoch = wn_DaysFromCivil(y, mo, d) * 86400LL +
                 (long long)h * 3600 + (long long)mi * 60 + s;
    }
    return ret;
}

int wn_X509_TimeValid(const wn_X509Cert* cert, time_t now)
{
    long long nb = 0, na = 0, n;
    int ret = WOLFNANO_SUCCESS;

    if (cert == NULL) {
        ret = WOLFNANO_E_INVALID_ARG;
    }
    if (ret == WOLFNANO_SUCCESS) {
        /* `now` is caller-supplied Unix time; the connect layer injects it from
         * the XTIME clock seam. No ambient clock call here, so the parser cannot
         * bypass a caller's configured time source. */
        ret = wn_CertTimeEpoch(cert->notBefore, cert->notBeforeLen, &nb);
        if (ret == WOLFNANO_SUCCESS) {
            ret = wn_CertTimeEpoch(cert->notAfter, cert->notAfterLen, &na);
        }
    }
    if (ret == WOLFNANO_SUCCESS) {
        n = (long long)now;
        if ((n < nb) || (n > na)) {
            ret = WOLFNANO_E_BAD_CERT;       /* not yet valid / expired */
        }
    }
    return ret;
}
#endif /* !WOLFNANO_NO_X509_TIME */
