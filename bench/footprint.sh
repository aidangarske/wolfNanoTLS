#!/bin/sh
# Footprint comparison: wolfNanoTLS slim TLS shell vs wolfSSL TLS layer.
# The crypto floor is identical (same wolfcrypt objects), so only the TLS layer
# differs. Sizes are total __TEXT bytes of -Os objects (host PORTABLE_C).
cd "$(dirname "$0")/.." || exit 1

OUT=build/footprint
rm -rf "$OUT"
mkdir -p "$OUT/nano" "$OUT/wolfssl"

NANO="-Os -ffunction-sections -fdata-sections -DWOLFSSL_USER_SETTINGS -I. -Iwolfssl -Iinclude/wolfnano -Isrc/shell_slim -DWOLFNANOTLS_TARGET_PORTABLE_C"
CMP="-Os -ffunction-sections -fdata-sections -DWOLFSSL_USER_SETTINGS -Ibench/cmp -Iwolfssl"

textsum() { size "$@" 2>/dev/null | awk 'NR>1{t+=$1} END{printf "%d", t}'; }

for f in wn_msg wn_keyschedule wn_transcript wn_record wn_keyshare \
         wn_serverhello wn_clienthello wn_connect; do
    cc $NANO -c src/shell_slim/$f.c -o "$OUT/nano/$f.o" 2>/dev/null
done
for f in tls13 tls; do
    cc $CMP -c wolfssl/src/$f.c -o "$OUT/wolfssl/$f.o" 2>/dev/null
done

NANO_SHELL=$(textsum "$OUT"/nano/*.o)
WSSL_TLS=$(textsum "$OUT"/wolfssl/*.o)
NANO_LOC=$(cat src/shell_slim/*.c | wc -l | tr -d ' ')
WSSL_LOC=$(cat wolfssl/src/tls13.c wolfssl/src/tls.c wolfssl/src/internal.c \
    wolfssl/src/ssl.c 2>/dev/null | wc -l | tr -d ' ')

echo "TLS-layer __TEXT footprint (bytes, -Os, host clang):"
echo "  wolfNanoTLS slim shell (full TLS 1.3 client)          : $NANO_SHELL"
echo "  wolfSSL TLS layer    (tls13.c + tls.c only)        : $WSSL_TLS"
echo
echo "TLS-layer source size (lines):"
echo "  wolfNanoTLS shell                                  : $NANO_LOC"
echo "  wolfSSL tls13.c+tls.c+internal.c+ssl.c          : $WSSL_LOC"
echo
echo "The crypto floor is the same wolfcrypt objects in both and is not counted."
echo "wolfNanoTLS omits internal.c and ssl.c entirely (the WOLFSSL object model),"
echo "which is the bulk of the wolfSSL TLS-layer footprint."
