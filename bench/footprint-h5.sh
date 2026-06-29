#!/bin/sh
# Smallest-build footprint on STM32H5 (Cortex-M33, Thumb-2), per config profile.
# For each profile builds the minimal wolfNano client two ways and reports the
# linked .text/.bss/.data (bytes):
#   small  = 16-bit Thumb SP (sp_armthumb.c, WOLFSSL_SP_ARM_THUMB_ASM) + SP_SMALL,
#            no symmetric asm  -> the smallest build (the headline size).
#   portC  = portable C generic math (WOLFSSL_SP_MATH_ALL)  -> reference.
# Also builds a full-wolfSSL TLS 1.3 cert client at the same scope for comparison.
# Static code size only (no run). Needs a complete arm-none-eabi toolchain.
set -u
ARM=${ARM_GNU_BIN:-$(echo /Applications/ArmGNUToolchain/*/arm-none-eabi/bin 2>/dev/null)}
CC=${CC:-$ARM/arm-none-eabi-gcc}; command -v "$CC" >/dev/null 2>&1 || CC=arm-none-eabi-gcc
SIZE=$(command -v ${ARM}/arm-none-eabi-size 2>/dev/null || echo arm-none-eabi-size)
OUT=${TMPDIR:-/tmp}/wn_fph5; mkdir -p "$OUT"
WC=wolfssl/wolfcrypt/src; WS=wolfssl/src
ARCH="-mcpu=cortex-m33 -mthumb"
OPT="-Os -ffunction-sections -fdata-sections -flto"
LINK="-flto -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs"
command -v "$CC" >/dev/null 2>&1 || { echo "SKIP (no arm-none-eabi-gcc)"; exit 0; }

cfg() { d="$OUT/cfg_$1"; mkdir -p "$d"; cp "configs/user_settings_$1.h" "$d/user_settings.h"; echo "$d"; }
INC="-I. -Iwolfssl -Iinclude/wolfnano -Isrc"
SHELL_SRC="src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c src/wn_connect.c"
FLOOR="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c $WC/aes.c"

# size cols: text data bss (GNU size default line 2)
sz() { "$SIZE" "$1" 2>/dev/null | awk 'NR==2{printf "%7s %6s %7s", $1,$2,$3}'; }

# build_variant <profile-cfg> <extra-defs> <crypto-srcs> <client> <variant> -> elf path
build() { # $1 cfg  $2 extradefs  $3 cryptosrcs  $4 client  $5 small|portC
    local cfgd t sp out o l
    cfgd="$(cfg "$1")"
    if [ "$5" = small ]; then t="-DWOLFNANO_TARGET_CORTEXM33_SMALL"; sp="$WC/sp_int.c $WC/sp_armthumb.c"
    else                      t="-DWOLFNANO_TARGET_PORTABLE_C";       sp="$WC/sp_int.c"; fi
    o="$OPT"; l="$LINK"
    # ML-DSA row must drop -flto: wc_mldsa.c trips an ArmGNU LTO + --gc-sections
    # live-code-removal bug (other rows unaffected); slight over-estimate.
    case "$1" in *mldsa*) o="-Os -ffunction-sections -fdata-sections";
                          l="-Wl,--gc-sections --specs=nano.specs --specs=nosys.specs";; esac
    out="$OUT/$1_$5.elf"
    $CC -I"$cfgd" $o $ARCH -DWOLFSSL_USER_SETTINGS $t $2 $INC \
        $FLOOR $sp $3 $SHELL_SRC "$4" $l -o "$out" 2>"$OUT/$1_$5.err"
    echo "$out"
}

printf '%-26s %18s   %18s\n' "profile" "small (text data bss)" "portC (text data bss)"
printf '%-26s %18s   %18s\n' "-------" "---------------------" "---------------------"

# 1) minimal: PSK + ECDHE X25519
C="$WC/curve25519.c $WC/fe_operations.c"
s=$(build minimal "" "$C" bench/min/wn_psk_client.c small)
p=$(build minimal "" "$C" bench/min/wn_psk_client.c portC)
printf '%-26s %18s   %18s\n' "PSK X25519 (minimal)" "$(sz "$s")" "$(sz "$p")"

# 2) psk_p256: PSK + ECDHE P-256
C="$WC/ecc.c $WC/asn.c"
s=$(build psk_p256 "" "$C" bench/min/wn_psk_client.c small)
p=$(build psk_p256 "" "$C" bench/min/wn_psk_client.c portC)
printf '%-26s %18s   %18s\n' "PSK P-256" "$(sz "$s")" "$(sz "$p")"

# 3) pqc: PSK + X25519MLKEM768 hybrid
C="$WC/curve25519.c $WC/fe_operations.c $WC/sha3.c $WC/wc_mlkem.c $WC/wc_mlkem_poly.c src/wn_hybrid.c"
s=$(build pqc "" "$C" bench/min/wn_psk_client.c small)
p=$(build pqc "" "$C" bench/min/wn_psk_client.c portC)
printf '%-26s %18s   %18s\n' "PSK X25519MLKEM768 (pqc)" "$(sz "$s")" "$(sz "$p")"

# 4) cert: X.509 P-256 (ECDSA/RSA verify)
C="$WC/sha512.c $WC/curve25519.c $WC/fe_operations.c $WC/ecc.c $WC/asn.c $WC/rsa.c src/wn_clienthello.c"
s=$(build cert "-DWOLFNANO_ALLOW_MALLOC" "$C" bench/min/wn_client.c small)
p=$(build cert "-DWOLFNANO_ALLOW_MALLOC" "$C" bench/min/wn_client.c portC)
printf '%-26s %18s   %18s\n' "cert / X.509 P-256" "$(sz "$s")" "$(sz "$p")"

# 5) cert_mldsa: X.509 + ML-DSA-44
C="$WC/sha512.c $WC/curve25519.c $WC/fe_operations.c $WC/ecc.c $WC/asn.c $WC/sha3.c $WC/wc_mldsa.c src/wn_clienthello.c"
s=$(build cert_mldsa "-DWOLFNANO_ALLOW_MALLOC" "$C" bench/min/wn_client.c small)
p=$(build cert_mldsa "-DWOLFNANO_ALLOW_MALLOC" "$C" bench/min/wn_client.c portC)
printf '%-26s %18s   %18s\n' "cert / X.509 + ML-DSA-44" "$(sz "$s")" "$(sz "$p")"

# --- wolfSSL TLS 1.3 cert client, same scope, for comparison (.text) ---
WS_CF="$OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -Ibench/min/ws -Iwolfssl"
$CC $WS_CF $WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c \
   $WC/logging.c $WC/coding.c $WC/sha256.c $WC/sha512.c $WC/hmac.c $WC/kdf.c $WC/aes.c \
   $WC/ecc.c $WC/asn.c $WC/rsa.c $WC/sp_int.c $WC/curve25519.c $WC/fe_operations.c \
   $WC/ed25519.c $WC/ge_operations.c \
   $WS/ssl.c $WS/internal.c $WS/tls.c $WS/tls13.c $WS/keys.c $WS/wolfio.c \
   bench/min/ws/ws_cert_client.c $LINK -o "$OUT/ws_cert.elf" 2>"$OUT/ws_cert.err"
echo
printf 'wolfSSL TLS 1.3 cert client (same scope): %s\n' "$(sz "$OUT/ws_cert.elf")"
echo "(.text data bss bytes; Cortex-M33 Thumb-2 -Os -flto --gc-sections, nano.specs)"
