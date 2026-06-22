/* error_test.c
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
 * Tests wn_ErrorToString: every defined code maps to a non-empty, distinct
 * string, and an unknown code falls back to a generic string (never NULL).
 */

#include "wolfnano.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

int main(void)
{
    static const int codes[] = {
        WOLFNANOTLS_SUCCESS, WOLFNANOTLS_E_INVALID_ARG, WOLFNANOTLS_E_CRYPTO,
        WOLFNANOTLS_E_UNSUPPORTED, WOLFNANOTLS_E_BAD_STATE, WOLFNANOTLS_E_UNEXPECTED_MSG,
        WOLFNANOTLS_E_DECODE, WOLFNANOTLS_E_BAD_MAC, WOLFNANOTLS_E_ILLEGAL_PARAM,
        WOLFNANOTLS_E_BAD_CERT, WOLFNANOTLS_E_CLOSED
    };
    const char* a;
    const char* b;
    int n = (int)(sizeof(codes) / sizeof(codes[0]));
    int i, j, distinct = 1, nonempty = 1;

    for (i = 0; i < n; i++) {
        a = wn_ErrorToString(codes[i]);
        if ((a == NULL) || (a[0] == '\0')) {
            nonempty = 0;
        }
        for (j = i + 1; j < n; j++) {
            b = wn_ErrorToString(codes[j]);
            if ((a != NULL) && (b != NULL) && (strcmp(a, b) == 0)) {
                distinct = 0;
            }
        }
    }
    check(nonempty, "every code maps to a non-empty string");
    check(distinct, "every code maps to a distinct string");

    a = wn_ErrorToString(12345);
    check((a != NULL) && (strcmp(a, "unknown error") == 0),
          "unknown code falls back to a generic string");

    if (fails == 0) {
        printf("error_test: all checks passed\n");
    }
    else {
        printf("error_test: %d FAILED\n", fails);
    }
    return fails == 0 ? 0 : 1;
}
