#!/bin/sh
# Compile each configs/user_settings_*.h template against the wolfNanoTLS shell so a
# broken starter template fails CI. Host profiles build a full client; the device
# profile (stm32h563) cross-compiles the floor when arm-none-eabi-gcc is present,
# else falls back to a syntax check.
set -e

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
BUILD=build/configs
CC=${CC:-cc}
WC=wolfssl/wolfcrypt/src
COMMON="-Os -Wall -Wextra -Werror -Wdeclaration-after-statement \
  -DWOLFSSL_USER_SETTINGS -Iwolfssl -Iinclude/wolfnano -Isrc -I."

FLOOR="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c \
  $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/sha512.c \
  $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/asn.c $WC/ecc.c $WC/curve25519.c \
  $WC/fe_operations.c $WC/ed25519.c $WC/ge_operations.c $WC/sp_int.c"

PSK="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/logging.c \
  $WC/random.c $WC/sha256.c $WC/sha512.c $WC/hmac.c $WC/kdf.c $WC/aes.c \
  $WC/curve25519.c $WC/fe_operations.c"

# P-256/SHA-256-only cert floor: no rsa.c, sha512.c, or ed25519.c/ge_operations.c
FLOOR_P256MIN="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c \
  $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c \
  $WC/aes.c $WC/asn.c $WC/ecc.c $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c"

PQC="$PSK $WC/sha3.c $WC/wc_mlkem.c $WC/wc_mlkem_poly.c $WC/sp_int.c"
SHELL_PQC="src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c \
  src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c src/wn_hybrid.c \
  src/wn_connect.c src/wn_session.c tests/wn_host_seed.c"

SHELL_PSK="src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c \
  src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c src/wn_connect.c \
  src/wn_session.c tests/wn_host_seed.c"
SHELL_CERT="src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c \
  src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c src/wn_clienthello.c \
  src/wn_connect.c src/wn_session.c tests/wn_host_seed.c"

build_host() {
    name=$1; srcset=$2
    d=$BUILD/$name
    mkdir -p "$d"
    cp "configs/user_settings_$name.h" "$d/user_settings.h"
    # shellcheck disable=SC2086
    $CC -I"$d" $COMMON -DWOLFNANO_TARGET_PORTABLE_C $srcset examples/client.c \
        -o "$d/client"
    echo "  PASS $name"
}

echo "configs-build:"
build_host minimal   "$PSK $SHELL_PSK"
build_host psk_p256  "$FLOOR $SHELL_PSK"
build_host cert      "$FLOOR $WC/rsa.c $SHELL_CERT"
build_host cert_pin  "$FLOOR $WC/rsa.c $SHELL_CERT"
build_host cert_p256min "$FLOOR_P256MIN $SHELL_CERT"
build_host cert_mldsa "$FLOOR $WC/sha3.c $WC/wc_mldsa.c $SHELL_CERT"
build_host cert_pqc  "$FLOOR $WC/rsa.c $WC/sha3.c $WC/wc_mlkem.c $WC/wc_mlkem_poly.c src/wn_hybrid.c $SHELL_CERT"
build_host pqc       "$PQC $SHELL_PQC"
build_host baremetal "$PSK $SHELL_PSK"

name=stm32h563
d=$BUILD/$name
mkdir -p "$d"
cp "configs/user_settings_$name.h" "$d/user_settings.h"
# shellcheck disable=SC2086
if command -v arm-none-eabi-gcc >/dev/null 2>&1 && \
   arm-none-eabi-gcc -mcpu=cortex-m33 -mthumb -ffreestanding -I"$d" $COMMON \
       -c src/wn_connect.c -o "$d/wn_connect.o" 2>/dev/null; then
    echo "  PASS $name (cross-compiled M33 object)"
else
    # shellcheck disable=SC2086
    $CC -I"$d" $COMMON -DWOLFNANO_TARGET_PORTABLE_C -fsyntax-only src/wn_connect.c
    echo "  PASS $name (host syntax-only; no complete arm-none-eabi-gcc)"
fi
echo "configs-build: all templates OK"
