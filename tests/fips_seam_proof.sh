#!/bin/sh
# Phase 5 seam proof: build the wolfNano seam test against a wolfSSL FIPS bundle,
# derive the in-core integrity hash for this exact binary (the standard
# per-artifact FIPS integration step), patch + rebuild the module, relink, and
# confirm the power-on self-tests pass through the unchanged wc_* seam.
set -u
FIPS_DIR=$1
LIB="$FIPS_DIR/src/.libs/libwolfssl.a"
SHELL_INC="-Iinclude/wolfnano -Isrc/shell_slim"
OUT=build/fips_seam_test

if [ "$(uname)" = "Darwin" ]; then
    LINK="-Wl,-force_load,$LIB -framework CoreFoundation -framework Security"
else
    LINK="-Wl,--whole-archive $LIB -Wl,--no-whole-archive"
fi

build() {
    cc -Os -Wall -Wextra -DWOLFSSL_USE_OPTIONS_H -I"$FIPS_DIR" $SHELL_INC \
       tests/fips_seam_test.c $LINK -o "$OUT" || exit 1
}

build
RESULT=$("./$OUT"); RC=$?
if [ "$RC" -eq 2 ]; then
    H=$(printf '%s\n' "$RESULT" | sed -n 's/^FIPS_INCORE_HASH=//p')
    echo "deriving in-core hash for this binary: $H"
    cp "$FIPS_DIR/wolfcrypt/src/fips_test.c" "$FIPS_DIR/wolfcrypt/src/fips_test.c.bak"
    sed "s/^\".*\";/\"$H\";/" "$FIPS_DIR/wolfcrypt/src/fips_test.c.bak" \
        > "$FIPS_DIR/wolfcrypt/src/fips_test.c"
    ( cd "$FIPS_DIR" && make ) >/tmp/wn_fips_relib.log 2>&1 || {
        echo "FAIL rebuilding FIPS module"; exit 1; }
    build
    RESULT=$("./$OUT"); RC=$?
fi
printf '%s\n' "$RESULT"
exit $RC
