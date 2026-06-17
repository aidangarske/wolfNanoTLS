/* wn_keyschedule.h
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
 * TLS 1.3 key schedule (RFC 8446 section 7.1) over the wc_* seam.
 * Logic ported from wolfSSL tls13.c; all buffers caller-provided (no alloc).
 */

#ifndef WN_KEYSCHEDULE_H
#define WN_KEYSCHEDULE_H

#include "wolfnano.h"

/* HKDF-Extract (RFC 5869) as used by the TLS 1.3 schedule. prk is Hash.length
 * bytes. A NULL/zero salt is treated as Hash.length zero bytes. */
WOLFNANOTLS_API int wn_Tls13_Extract(byte* prk, const byte* salt, word32 saltLen,
                                  const byte* ikm, word32 ikmLen, int digest);

/* HKDF-Expand-Label (RFC 8446 section 7.1): label is prefixed with "tls13 ". */
WOLFNANOTLS_API int wn_Tls13_ExpandLabel(byte* okm, word32 okmLen,
                                      const byte* secret, const char* label,
                                      const byte* info, word32 infoLen,
                                      int digest);

/* Derive-Secret(secret, label, transcriptHash): out is Hash.length bytes. */
WOLFNANOTLS_API int wn_Tls13_DeriveSecret(byte* out, const byte* secret,
                                       const char* label,
                                       const byte* transcriptHash,
                                       word32 hashLen, int digest);

#endif /* WN_KEYSCHEDULE_H */
