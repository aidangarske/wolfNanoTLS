/* wn_record.h
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
 * TLS 1.3 record protection (RFC 8446 section 5.2) with AES-GCM over the wc_*
 * seam. Caller-provided buffers, in-place AEAD; no allocation.
 */

#ifndef WN_RECORD_H
#define WN_RECORD_H

#include "wolfnano.h"

#define WN_RECORD_HEADER_SZ 5
#define WN_RECORD_TAG_SZ    16

/* Build a TLSCiphertext record into rec (header + AEAD ciphertext + tag).
 * rec must hold WN_RECORD_HEADER_SZ + contentLen + 1 + WN_RECORD_TAG_SZ bytes.
 * iv is the 12-byte write IV; the nonce is iv XOR seq. */
WOLFNANO_API int wn_Record_Protect(byte* rec, word32* recLen,
                                   const byte* key, word32 keyLen,
                                   const byte* iv, word32 seq,
                                   byte contentType,
                                   const byte* content, word32 contentLen);

/* Decrypt a TLSCiphertext record. content receives the inner content,
 * contentType the recovered type. content may alias rec + header. */
WOLFNANO_API int wn_Record_Unprotect(byte* content, word32* contentLen,
                                     byte* contentType,
                                     const byte* key, word32 keyLen,
                                     const byte* iv, word32 seq,
                                     const byte* rec, word32 recLen);

#endif /* WN_RECORD_H */
