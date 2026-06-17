/* wolfcrypt_test_main.c
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

/* Runs wolfSSL's own wolfcrypt test (wolfcrypt/test/test.c) against the wolfNano
 * floor. The test is compiled with the wolfNano config, so it is trimmed by
 * #ifdef to exactly the algorithms wolfNano supports. Complements the
 * wolfNano RFC-vector KATs in floor_test.c. */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/test/test.h>
#include <stdio.h>

int main(void)
{
    wc_test_ret_t ret;

    ret = wolfcrypt_test(NULL);
    printf("wolfcrypt_test ret=%ld\n", (long)ret);

    return (ret == 0) ? 0 : 1;
}
