#!/bin/sh
# Constant-time discipline: the wolfNano shell (src/) must compare MACs / secrets
# with ConstantCompare, never the variable-time memcmp / XMEMCMP. This guards the
# handshake's secret comparisons (server Finished, PSK binder) against timing
# side channels. tests/ and bench/ may use XMEMCMP for non-secret vector checks,
# so only src/ + include/ are scanned. Excludes the wolfssl submodule.
set -u

hits=$(grep -rnwE 'memcmp|XMEMCMP' --include='*.c' --include='*.h' src include 2>/dev/null)

if [ -n "$hits" ]; then
    echo "consttime-scan: FAIL (variable-time compare in src/; use ConstantCompare)"
    echo "$hits"
    exit 1
fi
echo "consttime-scan: clean (src/ include/ use ConstantCompare only)"
