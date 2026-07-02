/* wn_error.c
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
 * Maps a wolfNanoTLS return code to a short human-readable string for logging and
 * diagnostics. Returns a static string (no allocation); never NULL.
 */

#include "wolfnano.h"

const char* wn_ErrorToString(int err)
{
    const char* s;

    switch (err) {
        case WOLFNANO_SUCCESS:         s = "success";                  break;
        case WOLFNANO_E_INVALID_ARG:   s = "invalid argument";         break;
        case WOLFNANO_E_CRYPTO:        s = "crypto operation failed";  break;
        case WOLFNANO_E_UNSUPPORTED:   s = "unsupported";              break;
        case WOLFNANO_E_BAD_STATE:     s = "bad handshake state";      break;
        case WOLFNANO_E_UNEXPECTED_MSG:s = "unexpected message";       break;
        case WOLFNANO_E_DECODE:        s = "malformed message";        break;
        case WOLFNANO_E_BAD_MAC:       s = "authentication failure";   break;
        case WOLFNANO_E_ILLEGAL_PARAM: s = "illegal parameter";        break;
        case WOLFNANO_E_BAD_CERT:      s = "certificate failure";      break;
        case WOLFNANO_E_CLOSED:        s = "connection closed";        break;
        case WOLFNANO_E_X509_DECODE:   s = "malformed x509 certificate";break;
        case WOLFNANO_E_X509_CRITEXT:  s = "unhandled critical extension";break;
        default:                       s = "unknown error";           break;
    }

    return s;
}
