#!/bin/sh
# Enforce per-file line coverage from an lcov tracefile (wolfCOSE-grade gate).
# Reports coverage for every src/*.c and *.h, and fails if any file listed in
# the enforce list (default .github/ci/coverage-100.txt) is below 100%. Lines
# marked /* LCOV_EXCL_LINE */ are dropped by lcov, so 100% reflects reachable code.
set -u
INFO=${1:-cov.info}
ENFORCE=${2:-.github/ci/coverage-100.txt}

if [ ! -f "$INFO" ]; then
    echo "check_coverage: tracefile $INFO not found"
    exit 1
fi

awk -v enforce="$ENFORCE" '
  BEGIN {
    while ((getline l < enforce) > 0) {
      sub(/[ \t\r]+$/, "", l)
      if (l != "" && l !~ /^#/) { en[l] = 1 }
    }
    bad = 0
    printf "%-26s %7s %7s %8s\n", "file", "lines", "hit", "cover"
  }
  /^SF:/ { f = substr($0, 4); show = (f ~ /\/src\/[^\/]+\.(c|h)$/); total = 0; cov = 0; unc = "" }
  /^DA:/ {
    if (show) {
      split(substr($0, 4), a, ",")
      total++
      if (a[2] + 0 > 0) { cov++ }
      else { unc = unc " " a[1] }
    }
  }
  /^end_of_record/ {
    if (show && total > 0) {
      base = f; sub(/.*\//, "", base)
      pct = 100.0 * cov / total
      printf "%-26s %7d %7d %7.2f%%\n", base, total, cov, pct
      key = "src/" base
      if ((key in en) && cov < total) {
        printf "  >>> ENFORCE FAIL: %s at %d/%d lines (uncovered:%s)\n",
          key, cov, total, unc
        bad = 1
      }
    }
  }
  END {
    if (bad) { print "coverage gate: FAIL (enforced file below 100%)"; exit 1 }
    print "coverage gate: PASS (all enforced files at 100%)"
  }
' "$INFO"
