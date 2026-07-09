/* wn_servercert.h
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

/**
 * TLS 1.3 server Certificate + CertificateVerify encoders (RFC 8446 4.4.2/4.4.3).
 * The signing mirror of the client verify path; logic lifted from wolfSSL
 * tls13.c SendTls13Certificate / SendTls13CertificateVerify. No allocation on
 * the ECDSA/Ed25519 tiers; RSA/ML-DSA signing follow WOLFSSL_SMALL_STACK.
 */

#ifndef WN_SERVERCERT_H
#define WN_SERVERCERT_H

#include "wolfnano.h"
#include "wolfnano_crypto.h"

#if defined(WOLFNANO_SERVER) && defined(WOLFNANO_X509)

/* TLS 1.3 CertificateVerify signature schemes wolfNanoTLS can sign with. */
#define WN_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define WN_SIG_ECDSA_SECP384R1_SHA384 0x0503
#define WN_SIG_ED25519                0x0807
#define WN_SIG_RSA_PSS_RSAE_SHA256    0x0804
#define WN_SIG_RSA_PSS_RSAE_SHA384    0x0805
#define WN_SIG_RSA_PSS_RSAE_SHA512    0x0806

/* Encode a Certificate message (type 11) carrying one leaf cert (DER). */
WOLFNANO_LOCAL int wn_ServerCert_Build(byte* out, word32* outLen, word32 outCap,
                                       const byte* certDer, word32 certLen);

/* Encode a CertificateVerify message (type 15): sign the transcript hash th
 * under scheme with the private key keyDer (DER), framing scheme + signature. */
WOLFNANO_LOCAL int wn_ServerCertVerify_Sign(byte* out, word32* outLen,
                                            word32 outCap, word16 scheme,
                                            const byte* keyDer, word32 keyLen,
                                            const byte* th, word32 thLen,
                                            WC_RNG* rng);

#endif /* WOLFNANO_SERVER && WOLFNANO_X509 */

#endif /* WN_SERVERCERT_H */
