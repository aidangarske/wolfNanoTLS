#!/bin/sh
# Run a footprint harness N times (default 5) and report the result. The size
# builds are deterministic - LTO partitions by object-file input order, so every
# harness sorts its .o list (LC_ALL=C) before linking - therefore the N runs are
# byte-identical and no averaging is needed. This wrapper proves that: it reruns
# and, if any cell ever varies, prints the per-cell average and spread instead.
#   sh bench/footprint-average.sh bench/footprint-servers.sh [runs]
set -u
H=${1:?usage: sh bench/footprint-average.sh <harness.sh> [runs]}
N=${2:-5}
T=$(mktemp -d)
r=1
while [ "$r" -le "$N" ]; do
    printf 'run %d/%d...\n' "$r" "$N" >&2
    sh "$H" 2>/dev/null | grep -vE 'note:|ld:|warning:|is not implemented' > "$T/run$r"
    r=$((r + 1))
done

ident=1
r=2
while [ "$r" -le "$N" ]; do
    cmp -s "$T/run1" "$T/run$r" || ident=0
    r=$((r + 1))
done

if [ "$ident" = 1 ]; then
    printf '== %d runs byte-identical (deterministic) ==\n' "$N"
    cat "$T/run1"
else
    printf '== %d runs varied; per-cell average(~spread) ==\n' "$N"
    python3 - "$T" "$N" <<'PY'
import sys, glob
d, N = sys.argv[1], int(sys.argv[2])
runs = [open(f).read().splitlines() for f in sorted(glob.glob(d + "/run*"))]
for i in range(min(len(r) for r in runs)):
    lines = [r[i] for r in runs]
    label, cols = lines[0][:26], [ln[26:].split() for ln in lines]
    if cols[0] and all(len(c) == len(cols[0]) for c in cols):
        out = []
        for ci in range(len(cols[0])):
            vals = [cols[k][ci] for k in range(N)]
            ints = [int(v) for v in vals if v.lstrip('-').isdigit()]
            if len(ints) == N:
                a, sp = round(sum(ints) / N), max(ints) - min(ints)
                out.append(str(a) + ("" if sp == 0 else "~%d" % sp))
            else:
                out.append(vals[0])
        print(label + "".join("%11s" % x for x in out))
    else:
        print(lines[0])
PY
fi
rm -rf "$T"
