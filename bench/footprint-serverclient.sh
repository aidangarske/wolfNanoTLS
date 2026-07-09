#!/bin/sh
# Whole TLS 1.3 client+server DEVICE footprint (both roles in one binary): wolfNanoTLS vs mbedTLS 3.6.0 vs wolfSSL, built
# from source for Cortex-M33 (Thumb2, -Os, --gc-sections), every library scoped
# to the same minimal feature set. Reports .text bytes; static, no run.
# mbedTLS 4.1.0 rows: run bench/footprint-mbedtls4-servers.sh (tf-psa-crypto).
# Combined client+server device: bench/footprint-serverclient.sh.
set -u

ARM=${ARM_GNU_BIN:-$(echo /Applications/ArmGNUToolchain/*/arm-none-eabi/bin 2>/dev/null)}
CC=$ARM/arm-none-eabi-gcc
SIZE=$ARM/arm-none-eabi-size
MB=${MBEDTLS_DIR:-$HOME/mbedtls}
OUT=${TMPDIR:-/tmp}/wn_fpcs
WC=wolfssl/wolfcrypt/src
WS=wolfssl/src
ARCH="-mcpu=cortex-m33 -mthumb"
OPT="-Os -ffunction-sections -fdata-sections -flto"
NOLTO="-Os -ffunction-sections -fdata-sections"
LINK="-flto -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs"
GCLINK="-Wl,--gc-sections --specs=nano.specs --specs=nosys.specs"
mkdir -p "$OUT"

command -v "$CC" >/dev/null 2>&1 || { printf "\033[33mSKIP (no complete arm-none-eabi-gcc; set ARM_GNU_BIN)\033[0m\n"; exit 0; }
textsz() { "$SIZE" "$1" 2>/dev/null | awk 'NR==2{print $1}'; }
cfg() { d="$OUT/cfg_$1"; mkdir -p "$d"; cp "configs/user_settings_$1.h" "$d/user_settings.h"; echo "$d"; }

# ---- wolfNanoTLS server (WOLFNANO_SERVER; no wn_connect) ----
WN_BASE="$OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_SERVER -DWOLFNANO_TARGET_PORTABLE_C -I. -Iwolfssl -Iinclude/wolfnano -Isrc"
WN_BASE_NOLTO="$NOLTO $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_SERVER -DWOLFNANO_TARGET_PORTABLE_C -I. -Iwolfssl -Iinclude/wolfnano -Isrc"
WN_SUP_PSK="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c"
WN_SUP_P256="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/ecc.c $WC/asn.c $WC/sp_int.c"
WN_SUP="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/sha512.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c"
WN_SUP_PQC="$WN_SUP_PSK $WC/sha3.c $WC/wc_mlkem.c $WC/wc_mlkem_poly.c"
WN_SUP_MLDSA="$WN_SUP $WC/ecc.c $WC/asn.c $WC/sha3.c $WC/wc_mldsa.c"
WN_SHELL="src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c src/wn_clienthello.c src/wn_handshake.c src/wn_accept.c src/wn_connect.c"

$CC -I"$(cfg minimal)" $WN_BASE $WN_SUP_PSK $WN_SHELL bench/min/wn_psk_clientserver.c $LINK -o "$OUT/wn_psk.elf" 2>/dev/null
$CC -I"$(cfg psk_p256)" $WN_BASE $WN_SUP_P256 $WN_SHELL bench/min/wn_psk_clientserver.c $LINK -o "$OUT/wn_psk_p256.elf" 2>/dev/null
# cert rows use the native wn_x509 LITE parser (small-cert backend), matching the
# client harness; the client half of a combined device verifies with it.
$CC -I"$(cfg cert)" -DWOLFNANO_X509 -DWOLFNANO_X509_LITE $WN_BASE $WN_SUP $WC/ecc.c $WC/asn.c $WC/rsa.c $WC/ed25519.c $WC/ge_operations.c src/wn_x509.c src/wn_servercert.c $WN_SHELL bench/min/wn_clientserver.c $LINK -o "$OUT/wn_cert.elf" 2>/dev/null
# ML-DSA-44 server cert (scheme 0x0904); no -flto (wc_mldsa.c + gc-sections LTO bug on ArmGNU 14.2)
$CC -I"$(cfg cert_mldsa)" -DWOLFNANO_X509 -DWOLFNANO_X509_LITE -DWN_FP_SCHEME=0x0904 $WN_BASE_NOLTO $WN_SUP_MLDSA $WC/ed25519.c $WC/ge_operations.c src/wn_x509.c src/wn_servercert.c $WN_SHELL bench/min/wn_clientserver.c $GCLINK -o "$OUT/wn_cert_mldsa.elf" 2>/dev/null
# X25519MLKEM768 hybrid KEX PSK server
$CC -I"$(cfg pqc)" $WN_BASE $WN_SUP_PQC src/wn_hybrid.c $WN_SHELL bench/min/wn_psk_clientserver.c $LINK -o "$OUT/wn_pqc.elf" 2>/dev/null

# ---- mbedTLS 3.6.0 server (hard-minimized configs in bench/min) ----
mb_build() {
    cf="$OPT $ARCH -DMBEDTLS_CONFIG_FILE=\"$1\" -Ibench/min -I$MB/include -I$MB/library"
    d="$OUT/mb"; rm -rf "$d"; mkdir -p "$d"
    for f in "$MB"/library/*.c; do b=$(basename "$f"); [ "$b" = net_sockets.c ] && continue; [ "$b" = timing.c ] && continue
        $CC $cf -c "$f" -o "$d/$b.o" 2>/dev/null; done
    $CC $cf -c "$2" -o "$d/srv.o" 2>/dev/null && $CC $cf $(ls "$d"/*.o | LC_ALL=C sort) $LINK -o "$3" 2>/dev/null
}
[ -d "$MB" ] && mb_build mbedtls_config_psk_hardmin.h bench/min/mbed_psk_clientserver.c "$OUT/mb_psk.elf"
[ -d "$MB" ] && mb_build mbedtls_config_psk_p256_hardmin.h bench/min/mbed_psk_clientserver.c "$OUT/mb_psk_p256.elf"
[ -d "$MB" ] && mb_build mbedtls_config_tls_cs.h bench/min/mbed_clientserver.c "$OUT/mb_cert.elf"

# ---- full wolfSSL server (per-feature minimal configs in bench/min/ws_cs*) ----
ws_build() { # $1=config-dir $2=extra-src $3=driver $4=out
    $CC $OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -I"$1" -Iwolfssl \
      $WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c \
      $WC/logging.c $WC/coding.c $WC/sha256.c $WC/sha512.c $WC/hmac.c $WC/kdf.c $WC/aes.c \
      $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c $2 \
      $WS/ssl.c $WS/internal.c $WS/tls.c $WS/tls13.c $WS/keys.c $WS/wolfio.c \
      "$3" $LINK -o "$4" 2>/dev/null
}
ws_build bench/min/ws_cs_psk       "$WC/ecc.c $WC/asn.c"          bench/min/ws/ws_psk_clientserver.c    "$OUT/ws_psk.elf"
ws_build bench/min/ws_cs_psk_p256  "$WC/ecc.c $WC/asn.c"          bench/min/ws/ws_psk_clientserver.c    "$OUT/ws_psk_p256.elf"
ws_build bench/min/ws_cs           "$WC/ecc.c $WC/asn.c $WC/rsa.c $WC/ed25519.c $WC/ge_operations.c" bench/min/ws/ws_cert_clientserver.c "$OUT/ws_cert.elf"
ws_build bench/min/ws_cs_mldsa     "$WC/ecc.c $WC/asn.c $WC/sha3.c $WC/wc_mldsa.c $WC/rsa.c $WC/ed25519.c $WC/ge_operations.c" bench/min/ws/ws_cert_clientserver.c "$OUT/ws_mldsa.elf"
ws_build bench/min/ws_cs_pqc       "$WC/ecc.c $WC/asn.c $WC/sha3.c $WC/wc_mlkem.c $WC/wc_mlkem_poly.c" bench/min/ws/ws_psk_clientserver.c "$OUT/ws_pqc.elf"

na() { v=$(textsz "$1"); [ -n "$v" ] && echo "$v" || echo "-"; }
echo "Whole TLS 1.3 client+server DEVICE .text (Cortex-M33, -Os, gc-sections, minimal scope):"
printf '  %-24s %11s %11s %11s\n' "" wolfNanoTLS "mbed 3.6.0" wolfSSL
printf '  %-24s %11s %11s %11s\n' "PSK + ECDHE, X25519"    "$(na $OUT/wn_psk.elf)"       "$(na $OUT/mb_psk.elf)"      "$(na $OUT/ws_psk.elf)"
printf '  %-24s %11s %11s %11s\n' "PSK + ECDHE, P-256"     "$(na $OUT/wn_psk_p256.elf)"  "$(na $OUT/mb_psk_p256.elf)" "$(na $OUT/ws_psk_p256.elf)"
printf '  %-24s %11s %11s %11s\n' "cert / X.509, P-256"    "$(na $OUT/wn_cert.elf)"      "$(na $OUT/mb_cert.elf)"     "$(na $OUT/ws_cert.elf)"
printf '  %-24s %11s %11s %11s\n' "cert / X.509, ML-DSA-44" "$(na $OUT/wn_cert_mldsa.elf)" "N/A"                      "$(na $OUT/ws_mldsa.elf)"
printf '  %-24s %11s %11s %11s\n' "PSK, X25519MLKEM768"    "$(na $OUT/wn_pqc.elf)"       "N/A"                       "$(na $OUT/ws_pqc.elf)"
echo "  mbedTLS 4.1.0 rows: sh bench/footprint-mbedtls4-serverclient.sh"
