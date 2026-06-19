#!/bin/sh
# Enforce the true-no-allocator guarantee: no dynamic allocation in the wolfNanoTLS
# product source (src/ + include/). The bench/ harness and tests/ may allocate
# (measurement tools), so they are not scanned here. Excludes the wolfssl submodule.
# Word-boundary match so wc_*Free / *_free cleanup calls are not flagged.
set -u

pattern='malloc|calloc|realloc|free|XMALLOC|XFREE|XREALLOC|aligned_alloc|strdup|alloca'

hits=$(grep -rnwE "$pattern" --include='*.c' --include='*.h' src include 2>/dev/null \
    | grep -viE 'free software|see <https')

if [ -n "$hits" ]; then
    echo "no-alloc-scan: FAIL (dynamic allocation in src/ or include/)"
    echo "$hits"
    exit 1
fi
echo "no-alloc-scan: clean (src/ include/)"
