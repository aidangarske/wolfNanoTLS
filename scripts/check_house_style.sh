#!/bin/sh
# wolfNanoTLS house style for authored C (src/ include/ tests/ bench/): C-style
# comments only (no //), no em/en-dash, no tabs (4-space indent), no trailing
# whitespace. Excludes the wolfssl submodule. Prints all violations, exits 1 if any.
set -u

status=0
files=$(find src include tests bench -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null)

report() { # $1=label $2=hits
    if [ -n "$2" ]; then
        echo "house-style: $1"
        echo "$2"
        status=1
    fi
}

for f in $files; do
    report "C++ // comment ($f)" "$(grep -nE '(^|[^:])//' "$f" | grep -v 'https\?://')"
    report "em/en-dash ($f)"     "$(grep -nP '\xe2\x80\x94|\xe2\x80\x93' "$f" 2>/dev/null)"
    report "tab indent ($f)"     "$(grep -nP '\t' "$f" 2>/dev/null)"
    report "trailing space ($f)" "$(grep -nE ' +$' "$f")"
done

if [ "$status" -eq 0 ]; then
    echo "house-style: clean"
fi
exit "$status"
