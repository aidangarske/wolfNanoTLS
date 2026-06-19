#!/bin/sh
# Whole TLS 1.3 client footprint: wolfNano vs MbedTLS vs wolfSSL, all built from
# source for Cortex-M33 (Thumb2, -Os, --gc-sections), every library configured to
# the same minimal scope (ECDHE P-256 + X25519, AES-128-GCM, SHA-2, size knobs;
# cert build adds X.509 + ECDSA/RSA verify). Reports .text bytes. Static, no run.
#
# Needs a complete arm-none-eabi toolchain (with newlib) and an MbedTLS tree.
set -u

ARM=${ARM_GNU_BIN:-$(echo /Applications/ArmGNUToolchain/*/arm-none-eabi/bin 2>/dev/null)}
CC=$ARM/arm-none-eabi-gcc
SIZE=$ARM/arm-none-eabi-size
MB=${MBEDTLS_DIR:-$HOME/mbedtls}
OUT=${TMPDIR:-/tmp}/wn_fpc
WC=wolfssl/wolfcrypt/src
WS=wolfssl/src
ARCH="-mcpu=cortex-m33 -mthumb"
OPT="-Os -ffunction-sections -fdata-sections -flto"
LINK="-flto -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs"
mkdir -p "$OUT"

command -v "$CC" >/dev/null 2>&1 || { printf "\033[33mSKIP (no complete arm-none-eabi-gcc; set ARM_GNU_BIN)\033[0m\n"; exit 0; }
textsz() { "$SIZE" "$1" 2>/dev/null | awk 'NR==2{print $1}'; }

# ---- wolfNano (cert: bench/min/wnc with SHA-384; PSK: bench/min/wnc-psk SHA-256 only) ----
WN_CF="$OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -Ibench/min/wnc -I. -Iwolfssl -Iinclude/wolfnano -Isrc"
WN_CF_PSK="$OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -Ibench/min/wnc-psk -I. -Iwolfssl -Iinclude/wolfnano -Isrc"
WN_SUP="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/sha512.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c"
WN_SUP_PSK="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c"
WN_SHELL="src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c src/wn_connect.c"
$CC $WN_CF_PSK $WN_SUP_PSK $WN_SHELL bench/min/wn_psk_client.c $LINK -o "$OUT/wn_psk.elf" 2>/dev/null
# P-256 PSK (ECDHE secp256r1): ecc + asn + sp_int, X25519 gated out of the keyshare
WN_SUP_P256="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/ecc.c $WC/asn.c $WC/sp_int.c"
$CC $WN_CF_PSK -DWOLFNANO_HAVE_ECDHE_P256 $WN_SUP_P256 $WN_SHELL bench/min/wn_psk_client.c $LINK -o "$OUT/wn_psk_p256.elf" 2>/dev/null
$CC $WN_CF -DWOLFNANO_X509 -DWOLFNANO_HAVE_RSA_VERIFY -DWOLFNANO_FIPS -DWOLFNANO_ALLOW_MALLOC \
   $WN_SUP $WC/ecc.c $WC/asn.c $WC/rsa.c src/wn_clienthello.c $WN_SHELL \
   bench/min/wn_client.c $LINK -o "$OUT/wn_cert.elf" 2>/dev/null

# ---- MbedTLS (minimal configs in bench/min) ----
mb_build() { # $1=config $2=client $3=out
    local cf="$OPT $ARCH -DMBEDTLS_CONFIG_FILE=\"$1\" -Ibench/min -I$MB/include -I$MB/library"
    local d="$OUT/mb"; rm -rf "$d"; mkdir -p "$d"
    for f in "$MB"/library/*.c; do b=$(basename "$f"); [ "$b" = net_sockets.c ] && continue; [ "$b" = timing.c ] && continue
        $CC $cf -c "$f" -o "$d/$b.o" 2>/dev/null; done
    $CC $cf -c "$2" -o "$d/client.o" 2>/dev/null && $CC $cf "$d"/*.o $LINK -o "$3" 2>/dev/null
}
[ -d "$MB" ] && mb_build mbedtls_config_psk_hardmin.h bench/min/mbed_psk_client.c "$OUT/mb_psk.elf"
[ -d "$MB" ] && mb_build mbedtls_config_psk_p256_hardmin.h bench/min/mbed_psk_client.c "$OUT/mb_psk_p256.elf"
[ -d "$MB" ] && mb_build mbedtls_config_tls.h bench/min/mbed_client.c "$OUT/mb_cert.elf"

# ---- full wolfSSL (minimal config in bench/min/ws) ----
WS_CF="$OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -Ibench/min/ws -Iwolfssl"
$CC $WS_CF $WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c \
   $WC/logging.c $WC/coding.c $WC/sha256.c $WC/sha512.c $WC/hmac.c $WC/kdf.c $WC/aes.c \
   $WC/ecc.c $WC/asn.c $WC/rsa.c $WC/sp_int.c $WC/curve25519.c $WC/fe_operations.c \
   $WC/ed25519.c $WC/ge_operations.c \
   $WS/ssl.c $WS/internal.c $WS/tls.c $WS/tls13.c $WS/keys.c $WS/wolfio.c \
   bench/min/ws/ws_cert_client.c $LINK -o "$OUT/ws_cert.elf" 2>/dev/null

echo "Whole TLS 1.3 client .text (Cortex-M33, -Os, gc-sections, minimal scope):"
printf '  %-22s %10s %10s %10s\n' "" wolfNano MbedTLS wolfSSL
printf '  %-22s %10s %10s %10s\n' "PSK X25519 (no X509)" "$(textsz $OUT/wn_psk.elf)" "$(textsz $OUT/mb_psk.elf)" "-"
printf '  %-22s %10s %10s %10s\n' "PSK P-256 (no X509)" "$(textsz $OUT/wn_psk_p256.elf)" "$(textsz $OUT/mb_psk_p256.elf)" "-"
printf '  %-22s %10s %10s %10s\n' "cert / X509 (P-256)" "$(textsz $OUT/wn_cert.elf)" "$(textsz $OUT/mb_cert.elf)" "$(textsz $OUT/ws_cert.elf)"
