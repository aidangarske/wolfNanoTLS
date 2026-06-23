/* wn_serverhello.c
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
 * TLS 1.3 ServerHello parser over wn_msg. Structure per RFC 8446 4.1.3; logic
 * mirrors wolfSSL tls13.c DoTls13ServerHello. Pointers reference the input.
 */

#include "wn_serverhello.h"
#include "wn_msg.h"

#define WN_HS_SERVER_HELLO   2
#define WN_EXT_SUPPORTED_VER 43
#define WN_EXT_PRE_SHARED    41
#define WN_EXT_KEY_SHARE     51

/* HelloRetryRequest random sentinel (RFC 8446 4.1.3). */
static const byte wn_hrr_random[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

int wn_ServerHello_Parse(const byte* msg, word32 msgLen, wn_ServerHello* out)
{
    wn_Reader r;
    word32 hsLen;
    word32 extEnd;
    word16 extLen;
    word16 et;
    word16 el;
    word16 klen;
    byte type;
    byte sidLen;
    int ret = WOLFNANO_SUCCESS;

    if ((msg == NULL) || (out == NULL)) {
        ret = WOLFNANO_E_INVALID_ARG;
    }

    if (ret == WOLFNANO_SUCCESS) {
        out->random = NULL;
        out->keyShare = NULL;
        out->keyShareLen = 0;
        out->cipher = 0;
        out->group = 0;
        out->version = 0;
        out->pskSelected = -1;
        out->isHelloRetry = 0;

        wn_Reader_Init(&r, msg, msgLen);
        type  = wn_Read_U8(&r);
        hsLen = wn_Read_U24(&r);
        (void)wn_Read_U16(&r);                 /* legacy_version */
        out->random = wn_Read_Bytes(&r, 32);

        /* RFC 8446 4.1.3: a HelloRetryRequest is a ServerHello carrying the
         * fixed HRR random. Detect it here, before the normal extension parse,
         * because a real HRR's key_share is a 2-byte selected_group that would
         * otherwise fail that parse and mask the HRR. */
        if ((r.err == 0) && (out->random != NULL) &&
            (type == WN_HS_SERVER_HELLO)) {
            byte diff = 0;
            word32 i;
            for (i = 0; i < sizeof(wn_hrr_random); i++) {
                diff |= (byte)(out->random[i] ^ wn_hrr_random[i]);
            }
            if (diff == 0) {
                out->isHelloRetry = 1;
            }
        }

        if (out->isHelloRetry == 0) {
            sidLen = wn_Read_U8(&r);
            (void)wn_Read_Bytes(&r, sidLen);   /* legacy_session_id_echo */
            out->cipher = wn_Read_U16(&r);
            (void)wn_Read_U8(&r);              /* legacy_compression_method */

            extLen = wn_Read_U16(&r);
            extEnd = r.pos + extLen;
            if (extEnd > msgLen) {      /* extensions overrun the message: reject */
                extEnd = msgLen;        /* and bound the loop to the buffer */
                r.err = 1;
            }
            while ((r.pos < extEnd) && (r.err == 0)) {
                et = wn_Read_U16(&r);
                el = wn_Read_U16(&r);
                if (et == WN_EXT_KEY_SHARE) {
                    out->group = wn_Read_U16(&r);
                    klen = wn_Read_U16(&r);
                    out->keyShare = wn_Read_Bytes(&r, klen);
                    out->keyShareLen = klen;
                }
                else if (et == WN_EXT_SUPPORTED_VER) {
                    out->version = wn_Read_U16(&r);
                }
                else if (et == WN_EXT_PRE_SHARED) {
                    out->pskSelected = (int)wn_Read_U16(&r);
                }
                else {
                    (void)wn_Read_Bytes(&r, el);
                }
            }

            if ((r.err != 0) || (type != WN_HS_SERVER_HELLO) ||
                (hsLen != (msgLen - 4)) || (out->random == NULL)) {
                ret = WOLFNANO_E_INVALID_ARG;
            }
        }
    }

    return ret;
}
