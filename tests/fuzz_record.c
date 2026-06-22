/* fuzz_record.c
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
 * libFuzzer harness for the TLS 1.3 record decryptor. Feeds arbitrary bytes as
 * a TLSCiphertext to wn_Record_Unprotect with a fixed key/iv; almost all inputs
 * fail the AEAD tag, but the parser must never read or write out of bounds on
 * any input (ASan-instrumented). This is the session's untrusted-input entry.
 */

#include "wn_record.h"
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static const byte key[16] = { 0 };
    static const byte iv[12] = { 0 };
    byte out[8192];
    byte ctype = 0;
    word32 outLen = 0;

    if (size > sizeof(out)) {
        return 0;
    }
    (void)wn_Record_Unprotect(out, &outLen, &ctype, key, sizeof(key), iv, 0,
                              (const byte*)data, (word32)size);
    return 0;
}
