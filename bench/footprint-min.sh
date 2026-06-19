#!/bin/sh
# Minimal footprint comparison: wolfNanoTLS vs MbedTLS for one TLS 1.3 ciphersuite's
# crypto, per scope. Both built bare-minimal for Cortex-M33 (Thumb2, -Os, no asm),
# -ffunction-sections + --gc-sections so the linker keeps only each scope's code;
# sized with arm-none-eabi-size. Static code size only (no run).
set -u

BIN=${ARM_GNU_BIN:-$(echo /Applications/ArmGNUToolchain/*/arm-none-eabi/bin 2>/dev/null)}
CC=$BIN/arm-none-eabi-gcc
SIZE=$BIN/arm-none-eabi-size
OUT=${TMPDIR:-/tmp}/wn_fpmin
mkdir -p "$OUT"

command -v "$CC" >/dev/null 2>&1 || { echo "SKIP footprint-min (no arm-none-eabi-gcc; set ARM_GNU_BIN)"; exit 0; }

ARCH="-mcpu=cortex-m33 -mthumb"
OPT="-Os -ffunction-sections -fdata-sections"
LINK="-Wl,--gc-sections --specs=nano.specs --specs=nosys.specs"

WC=wolfssl/wolfcrypt/src
WN_FLOOR="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c \
  $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/aes.c $WC/hmac.c \
  $WC/kdf.c $WC/ecc.c $WC/asn.c $WC/sp_int.c $WC/sp_c32.c"
WN_CF="$OPT $ARCH -DWOLFSSL_USER_SETTINGS -Ibench/min -I. -Iwolfssl"

MB=$HOME/mbedtls
MB_SRC="$MB/library/aes.c $MB/library/gcm.c $MB/library/cipher.c \
  $MB/library/cipher_wrap.c $MB/library/sha256.c \
  $MB/library/md.c $MB/library/hkdf.c \
  $MB/library/ecp.c $MB/library/ecp_curves.c $MB/library/ecdsa.c \
  $MB/library/ecdh.c $MB/library/bignum.c $MB/library/bignum_core.c \
  $MB/library/asn1parse.c $MB/library/asn1write.c $MB/library/platform.c \
  $MB/library/platform_util.c $MB/library/constant_time.c"
MB_CF="$OPT $ARCH -DMBEDTLS_CONFIG_FILE=\"mbedtls_config_min.h\" -Ibench/min -I$MB/include"

textsize() { $SIZE "$1" 2>/dev/null | awk 'NR==2{print $1}'; }

printf '%-12s %14s %14s %10s\n' scope wolfNanoTLS MbedTLS smaller
for s in AEAD VERIFY SIGNVERIFY HANDSHAKE; do
    $CC $WN_CF -DFP_$s $WN_FLOOR bench/min/wn_min.c $LINK \
        -o "$OUT/wn_$s.elf" 2>"$OUT/wn_$s.err"
    $CC $MB_CF -DFP_$s $MB_SRC bench/min/mbed_min.c $LINK \
        -o "$OUT/mb_$s.elf" 2>"$OUT/mb_$s.err"
    wn=$(textsize "$OUT/wn_$s.elf"); mb=$(textsize "$OUT/mb_$s.elf")
    wn=${wn:-build-failed}; mb=${mb:-build-failed}
    if [ "$wn" -gt 0 ] 2>/dev/null && [ "$mb" -gt 0 ] 2>/dev/null; then
        ratio=$(awk "BEGIN{printf \"%.2fx\", $mb/$wn}")
    else
        ratio="-"
    fi
    printf '%-12s %14s %14s %10s\n' "$s" "$wn" "$mb" "$ratio"
done
echo "(.text bytes, Cortex-M33 Thumb2 -Os, gc-sections; smaller = MbedTLS/wolfNanoTLS)"
