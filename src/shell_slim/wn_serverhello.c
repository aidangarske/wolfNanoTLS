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

        wn_Reader_Init(&r, msg, msgLen);
        type  = wn_Read_U8(&r);
        hsLen = wn_Read_U24(&r);
        (void)wn_Read_U16(&r);                 /* legacy_version */
        out->random = wn_Read_Bytes(&r, 32);
        sidLen = wn_Read_U8(&r);
        (void)wn_Read_Bytes(&r, sidLen);       /* legacy_session_id_echo */
        out->cipher = wn_Read_U16(&r);
        (void)wn_Read_U8(&r);                  /* legacy_compression_method */

        extLen = wn_Read_U16(&r);
        extEnd = r.pos + extLen;
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

    return ret;
}
