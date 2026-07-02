#!/bin/sh
# Constant-time discipline: the wolfNanoTLS shell (src/) must compare MACs / secrets
# with ConstantCompare, never the variable-time memcmp / XMEMCMP. This guards the
# handshake's secret comparisons (server Finished, PSK binder) against timing
# side channels. tests/ and bench/ may use XMEMCMP for non-secret vector checks,
# so only src/ + include/ are scanned. Excludes the wolfssl submodule.
#
# Exception: a line explicitly annotated "ct-public" compares public, non-secret
# data (e.g. X.509 OIDs / DigestInfo), where a variable-time compare leaks
# nothing and is faster. Those are allowed; every other memcmp/XMEMCMP fails.
set -u

hits=$(grep -rnwE 'memcmp|XMEMCMP' --include='*.c' --include='*.h' src include 2>/dev/null \
       | grep -v 'ct-public')

if [ -n "$hits" ]; then
    echo "consttime-scan: FAIL (variable-time compare in src/; use ConstantCompare)"
    echo "$hits"
    exit 1
fi
echo "consttime-scan: clean (src/ include/ use ConstantCompare only)"
