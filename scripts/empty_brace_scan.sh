#!/bin/sh
# Flag bare scope blocks in wolfNanoTLS-authored C: a standalone `{` on its own line
# following a statement end (`;` or `}`). Function definitions (`)` on the prior
# line) and same-line control braces are allowed. Excludes the wolfssl submodule.
set -u

status=0
files=$(find src include tests bench -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null)

for f in $files; do
    hits=$(awk '
        prev ~ /[;}]$/ && /^[[:space:]]*\{[[:space:]]*$/ { print FILENAME ":" NR }
        { prev = $0 }
    ' "$f")
    if [ -n "$hits" ]; then
        echo "bare scope block:"
        echo "$hits"
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "empty-brace-scan: clean"
fi
exit "$status"
