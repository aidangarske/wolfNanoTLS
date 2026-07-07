/* fuzz_clienthello.c
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
 * libFuzzer harness for the TLS 1.3 server-side ClientHello parser. Feeds
 * arbitrary bytes to wn_ClientHello_Parse (the new server wire parser); the
 * sticky-error reader must never read out of bounds or crash on any input
 * (ASan-instrumented), including the PSK-binder and signature_algorithms fields.
 */

#include "wn_clienthello.h"
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    wn_ClientHello ch;

    if (size > 0) {
        if (wn_ClientHello_Parse((const byte*)data, (word32)size, &ch) == 0) {
            (void)wn_ClientHello_HasSigAlg(&ch, 0x0403);
        }
    }
    return 0;
}
