#!/bin/sh
# Fail if an ELF contains any forbidden wolfcrypt symbol. Proves a minimized
# build truly excludes the algorithms its config disabled (dead-strip is not
# enough on its own; this asserts the symbols are gone).
# Usage: symbol_audit.sh <nm-tool> <elf> <forbidden-egrep-pattern>...
set -u
NM=$1
ELF=$2
shift 2

syms=$("$NM" "$ELF" 2>/dev/null | awk '{print $3}')
rc=0
for pat in "$@"; do
    if echo "$syms" | grep -qiE "$pat"; then
        echo "FORBIDDEN symbol(s) matching '$pat' in $ELF:"
        echo "$syms" | grep -iE "$pat" | sed 's/^/    /' | head -5
        rc=1
    fi
done
if [ "$rc" -eq 0 ]; then
    echo "symbol-audit: clean ($ELF)"
fi
exit $rc
