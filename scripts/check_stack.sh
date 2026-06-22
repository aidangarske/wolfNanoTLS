#!/bin/sh
# Fail if any wolfNano (wn_) function's stack frame exceeds the budget, from
# -fstack-usage .su files. Keeps the embedded stack footprint from regressing
# (the cert handshake driver was reduced from ~13 KB to ~3.9 KB; see Footprint).
set -u
MAX=${STACK_MAX:-5120}
bad=0
big=""

for f in "$@"; do
    [ -f "$f" ] || continue
    while IFS="$(printf '\t')" read -r name size kind; do
        case "$name" in
            *wn_*)
                if [ "${size:-0}" -gt "$MAX" ]; then
                    echo "  >>> STACK FAIL: $name = $size > $MAX"
                    big="$big $name"
                    bad=1
                fi
                ;;
        esac
    done < "$f"
done

if [ "$bad" -eq 0 ]; then
    echo "stack gate: PASS (all wn_ frames <= ${MAX} bytes)"
else
    echo "stack gate: FAIL ($big)"
    exit 1
fi
