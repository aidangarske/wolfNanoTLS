#!/bin/sh
# wolfNanoTLS product-source allocation gate (src/ + include/; bench/ and tests/
# are not scanned; wolfssl submodule excluded).
#  1. No raw libc allocation, ever.
#  2. The portable wolfSSL macros (XMALLOC/XFREE/XREALLOC) are allowed ONLY inside
#     a WOLFSSL_SMALL_STACK guard, so they compile out under WOLFSSL_NO_MALLOC.
#     The no-malloc build's zero-allocation is then proven at runtime by
#     make noalloc-crypto / noalloc-handshake.
set -u

fail=0

# 1. raw libc allocation: always forbidden (word-boundary so wc_*Free / *_free
#    cleanup calls are not flagged).
raw='malloc|calloc|realloc|free|aligned_alloc|posix_memalign|memalign|strdup|alloca'
raw_hits=$(grep -rnwE "$raw" --include='*.c' --include='*.h' src include 2>/dev/null \
    | grep -viE 'free software|see <https')
if [ -n "$raw_hits" ]; then
    echo "no-alloc-scan: FAIL (raw libc allocation in src/ or include/)"
    echo "$raw_hits"
    fail=1
fi

# 2. XMALLOC/XFREE/XREALLOC must sit inside a WOLFSSL_SMALL_STACK #if guard.
guard_hits=$(find src include -name '*.c' -o -name '*.h' 2>/dev/null | while read -r f; do
    awk '
      # cur[d]=1 means the currently-active branch at depth d requires
      # WOLFSSL_SMALL_STACK to be defined; gv[d] records the guard polarity so
      # #else can flip it correctly.
      /^[ \t]*#[ \t]*ifdef[ \t]+WOLFSSL_SMALL_STACK([ \t]|$)/ { depth++; cur[depth]=1; gv[depth]="pos"; next }
      /^[ \t]*#[ \t]*ifndef[ \t]+WOLFSSL_SMALL_STACK([ \t]|$)/ { depth++; cur[depth]=0; gv[depth]="neg"; next }
      /^[ \t]*#[ \t]*if/ {
          depth++;
          if ($0 ~ /defined[ \t]*\([ \t]*WOLFSSL_SMALL_STACK/ && $0 !~ /!/) { cur[depth]=1; gv[depth]="pos" }
          else if ($0 ~ /WOLFSSL_SMALL_STACK/ && $0 ~ /!/) { cur[depth]=0; gv[depth]="neg" }
          else { cur[depth]=0; gv[depth]="none" }
          next
      }
      /^[ \t]*#[ \t]*elif/  { if (depth>0) { cur[depth]=0; gv[depth]="none" } next }
      /^[ \t]*#[ \t]*else/  { if (depth>0) { cur[depth]=(gv[depth]=="neg")?1:0 } next }
      /^[ \t]*#[ \t]*endif/ { if (depth>0) { cur[depth]=0; gv[depth]=""; depth-- } next }
      /(^|[^A-Za-z0-9_])(XMALLOC|XFREE|XREALLOC)([^A-Za-z0-9_]|$)/ {
          g=0; for (i=1;i<=depth;i++) if (cur[i]) g=1;
          if (!g) print FILENAME":"FNR": "$0
      }
    ' "$f"
done)
if [ -n "$guard_hits" ]; then
    echo "no-alloc-scan: FAIL (unguarded XMALLOC/XFREE/XREALLOC - must be inside #ifdef WOLFSSL_SMALL_STACK)"
    echo "$guard_hits"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "no-alloc-scan: clean (src/ include/)"
