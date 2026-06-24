/* wn_clienthello.c
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
 * TLS 1.3 ClientHello encoder over wn_msg. Structure per RFC 8446 4.1.2; logic
 * mirrors wolfSSL tls13.c SendTls13ClientHello. No allocation.
 */

#include "wn_clienthello.h"
#include "wn_keyshare.h"
#include "wn_msg.h"

#define WN_HS_CLIENT_HELLO   1
#define WN_EXT_SUPPORTED_GRP 10
#define WN_EXT_SIG_ALGS      13
#define WN_EXT_SUPPORTED_VER 43
#define WN_EXT_KEY_SHARE     51

int wn_ClientHello_Build(byte* out, word32* outLen, word32 outCap,
                         const byte* random32, const byte* sessionId,
                         word32 sessionIdLen, const byte* pub,
                         word32 pubLen)
{
    wn_Writer w;
    word32 hsLen;
    word32 extLen;
    int ret = WOLFNANOTLS_SUCCESS;

    if ((out == NULL) || (outLen == NULL) || (random32 == NULL) ||
        (pub == NULL) || (pubLen != WN_DEFAULT_PUB_SZ) || (sessionIdLen > 32)) {
        ret = WOLFNANOTLS_E_INVALID_ARG;
    }

    if (ret == WOLFNANOTLS_SUCCESS) {
        wn_Writer_Init(&w, out, outCap);

        wn_Write_U8(&w, WN_HS_CLIENT_HELLO);
        hsLen = wn_Write_LenStart(&w, 3);

        wn_Write_U16(&w, 0x0303);              /* legacy_version */
        wn_Write_Bytes(&w, random32, 32);      /* random */

        wn_Write_U8(&w, (byte)sessionIdLen);   /* legacy_session_id */
        if (sessionIdLen > 0) {
            wn_Write_Bytes(&w, sessionId, sessionIdLen);
        }

        wn_Write_U16(&w, 2);                   /* cipher_suites length */
        wn_Write_U16(&w, WN_CIPHER_AES_128_GCM_SHA256);

        wn_Write_U8(&w, 1);                    /* legacy_compression_methods */
        wn_Write_U8(&w, 0);

        extLen = wn_Write_LenStart(&w, 2);     /* extensions */

        /* supported_versions: [TLS 1.3] */
        wn_Write_U16(&w, WN_EXT_SUPPORTED_VER);
        wn_Write_U16(&w, 3);
        wn_Write_U8(&w, 2);
        wn_Write_U16(&w, 0x0304);

        /* supported_groups: [configured (EC)DHE group] */
        wn_Write_U16(&w, WN_EXT_SUPPORTED_GRP);
        wn_Write_U16(&w, 4);
        wn_Write_U16(&w, 2);
        wn_Write_U16(&w, WN_DEFAULT_GROUP);

        /* signature_algorithms */
        wn_Write_U16(&w, WN_EXT_SIG_ALGS);
#ifdef WOLFNANOTLS_FIPS
        wn_Write_U16(&w, 6);
        wn_Write_U16(&w, 4);
        wn_Write_U16(&w, 0x0403);              /* ecdsa_secp256r1_sha256 */
        wn_Write_U16(&w, 0x0804);              /* rsa_pss_rsae_sha256 */
#elif defined(WOLFSSL_HAVE_MLDSA)
        wn_Write_U16(&w, 10);
        wn_Write_U16(&w, 8);
        wn_Write_U16(&w, WN_MLDSA_SCHEME);              /* ML-DSA (level via WOLFNANOTLS_MLDSA_LEVEL) */
        wn_Write_U16(&w, 0x0807);              /* ed25519 */
        wn_Write_U16(&w, 0x0403);              /* ecdsa_secp256r1_sha256 */
        wn_Write_U16(&w, 0x0804);              /* rsa_pss_rsae_sha256 */
#else
        wn_Write_U16(&w, 8);
        wn_Write_U16(&w, 6);
        wn_Write_U16(&w, 0x0807);              /* ed25519 */
        wn_Write_U16(&w, 0x0403);              /* ecdsa_secp256r1_sha256 */
        wn_Write_U16(&w, 0x0804);              /* rsa_pss_rsae_sha256 */
#endif

        /* key_share: one entry for the configured group */
        wn_Write_U16(&w, WN_EXT_KEY_SHARE);
        wn_Write_U16(&w, (word16)(2 + 2 + 2 + pubLen));
        wn_Write_U16(&w, (word16)(2 + 2 + pubLen));
        wn_Write_U16(&w, WN_DEFAULT_GROUP);
        wn_Write_U16(&w, (word16)pubLen);
        wn_Write_Bytes(&w, pub, pubLen);

        wn_Write_LenEnd(&w, extLen, 2);        /* extensions length */
        wn_Write_LenEnd(&w, hsLen, 3);         /* handshake length */

        if (w.err != 0) {
            ret = WOLFNANOTLS_E_INVALID_ARG;
        }
        else {
            *outLen = w.len;
        }
    }

    return ret;
}
