#!/bin/sh
# Whole TLS 1.3 client footprint: wolfNanoTLS vs MbedTLS vs wolfSSL, all built from
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

# ---- wolfNanoTLS: built from the public configs/ starter templates (one source of
# truth, so the footprint reproduces from the same user_settings.h a user ships) ----
cfg() { d="$OUT/cfg_$1"; mkdir -p "$d"; cp "configs/user_settings_$1.h" "$d/user_settings.h"; echo "$d"; }
WN_BASE="$OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -I. -Iwolfssl -Iinclude/wolfnano -Isrc"
WN_SUP="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/sha512.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c"
WN_SUP_PSK="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c"
WN_SHELL="src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c src/wn_connect.c"
$CC -I"$(cfg minimal)" $WN_BASE $WN_SUP_PSK $WN_SHELL bench/min/wn_psk_client.c $LINK -o "$OUT/wn_psk.elf" 2>/dev/null
# P-256 PSK (ECDHE secp256r1): ecc + asn + sp_int, X25519 gated out of the keyshare
WN_SUP_P256="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/ecc.c $WC/asn.c $WC/sp_int.c"
$CC -I"$(cfg psk_p256)" $WN_BASE $WN_SUP_P256 $WN_SHELL bench/min/wn_psk_client.c $LINK -o "$OUT/wn_psk_p256.elf" 2>/dev/null
# cert / X.509 P-256: wolfSSL asn.c (default) and native wn_x509 (WOLFNANO_X509_LITE)
$CC -I"$(cfg cert)" $WN_BASE \
   $WN_SUP $WC/ecc.c $WC/asn.c $WC/rsa.c src/wn_clienthello.c $WN_SHELL \
   bench/min/wn_client.c $LINK -o "$OUT/wn_cert.elf" 2>/dev/null
$CC -I"$(cfg cert)" -DWOLFNANO_X509_LITE $WN_BASE \
   $WN_SUP $WC/ecc.c $WC/asn.c $WC/rsa.c src/wn_x509.c src/wn_clienthello.c $WN_SHELL \
   bench/min/wn_client.c $LINK -o "$OUT/wn_cert_lite.elf" 2>/dev/null
# cert / X.509 P-256 minimal (private PKI): single-curve P-256 + SHA-256 only, no
# SHA-384/512, no P-384, no RSA, no Ed25519; drops rsa.c/sha512.c/ed25519.c.
WN_SUP_P256MIN="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c $WC/logging.c $WC/coding.c $WC/sha256.c $WC/hmac.c $WC/kdf.c $WC/aes.c $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c $WC/ecc.c $WC/asn.c"
$CC -I"$(cfg cert_p256min)" -DWOLFNANO_X509_LITE $WN_BASE \
   $WN_SUP_P256MIN src/wn_x509.c src/wn_clienthello.c $WN_SHELL \
   bench/min/wn_client.c $LINK -o "$OUT/wn_cert_p256min.elf" 2>/dev/null
# cert / X.509 + X25519MLKEM768 hybrid KEX (PQC key exchange + classical cert)
$CC -I"$(cfg cert_pqc)" -DWOLFNANO_X509_LITE $WN_BASE \
   $WN_SUP $WC/sha3.c $WC/wc_mlkem.c $WC/wc_mlkem_poly.c \
   $WC/ecc.c $WC/asn.c $WC/rsa.c src/wn_x509.c src/wn_clienthello.c src/wn_hybrid.c $WN_SHELL \
   bench/min/wn_client.c $LINK -o "$OUT/wn_cert_pqc.elf" 2>/dev/null
# PSK + X25519MLKEM768 hybrid (post-quantum): adds ML-KEM-768 + SHA3 + wn_hybrid
WN_SUP_PQC="$WN_SUP_PSK $WC/sha3.c $WC/wc_mlkem.c $WC/wc_mlkem_poly.c"
$CC -I"$(cfg pqc)" $WN_BASE $WN_SUP_PQC src/wn_hybrid.c $WN_SHELL \
   bench/min/wn_psk_client.c $LINK -o "$OUT/wn_psk_pqc.elf" 2>/dev/null
# cert / X.509 with ML-DSA-44 server-cert verify (post-quantum signature): ECDSA
# chain + ML-DSA-44 leaf, no RSA; adds SHA3 + wc_mldsa over the ECC cert build.
# Built without -flto: wc_mldsa.c trips an LTO + --gc-sections live-code removal
# bug in ArmGNU 14.2 (the other rows are unaffected), so this row is a slight
# over-estimate vs the -flto rows above.
WN_SUP_MLDSA="$WN_SUP $WC/ecc.c $WC/asn.c $WC/sha3.c $WC/wc_mldsa.c"
WN_BASE_NOLTO="-Os -ffunction-sections -fdata-sections $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -I. -Iwolfssl -Iinclude/wolfnano -Isrc"
# ML-DSA-44 leaf: wolfSSL asn.c (default) and native wn_x509 (WOLFNANO_X509_LITE)
# for the ECDSA chain + ML-DSA CertificateVerify.
$CC -I"$(cfg cert_mldsa)" $WN_BASE_NOLTO \
   $WN_SUP_MLDSA src/wn_clienthello.c $WN_SHELL \
   bench/min/wn_client.c -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs \
   -o "$OUT/wn_cert_mldsa.elf" 2>/dev/null
$CC -I"$(cfg cert_mldsa)" -DWOLFNANO_X509_LITE $WN_BASE_NOLTO \
   $WN_SUP_MLDSA src/wn_x509.c src/wn_clienthello.c $WN_SHELL \
   bench/min/wn_client.c -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs \
   -o "$OUT/wn_cert_mldsa_lite.elf" 2>/dev/null

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
printf '  %-22s %10s %10s %10s\n' "" wolfNanoTLS MbedTLS wolfSSL
printf '  %-22s %10s %10s %10s\n' "PSK X25519 (no X509)" "$(textsz $OUT/wn_psk.elf)" "$(textsz $OUT/mb_psk.elf)" "-"
printf '  %-22s %10s %10s %10s\n' "PSK P-256 (no X509)" "$(textsz $OUT/wn_psk_p256.elf)" "$(textsz $OUT/mb_psk_p256.elf)" "-"
printf '  %-22s %10s %10s %10s\n' "cert / X509 (P-256)" "$(textsz $OUT/wn_cert_lite.elf)" "$(textsz $OUT/mb_cert.elf)" "$(textsz $OUT/ws_cert.elf)"
printf '  %-22s %10s %10s %10s\n' "PSK X25519MLKEM768" "$(textsz $OUT/wn_psk_pqc.elf)" "-" "-"
printf '  %-22s %10s %10s %10s\n' "cert / X509 (ML-DSA-44)" "$(textsz $OUT/wn_cert_mldsa_lite.elf)" "-" "-"
echo "  (cert rows show WOLFNANO_X509_LITE; default asn.c backend is larger, see below)"
echo ""
echo "wolfNanoTLS X.509 backend .text (wolfSSL asn.c [default] vs native wn_x509 [X509_LITE]):"
printf '  %-24s asn.c %8s   lite %8s\n' "cert / X509 (P-256)" "$(textsz $OUT/wn_cert.elf)" "$(textsz $OUT/wn_cert_lite.elf)"
printf '  %-24s asn.c %8s   lite %8s\n' "cert / X509 (ML-DSA-44)" "$(textsz $OUT/wn_cert_mldsa.elf)" "$(textsz $OUT/wn_cert_mldsa_lite.elf)"
printf '  %-24s   lite %8s   (P-256 private PKI: no SHA-384/512, P-384, RSA)\n' "cert / X509 (P-256 min)" "$(textsz $OUT/wn_cert_p256min.elf)"
printf '  %-24s   lite %8s   (X25519MLKEM768 hybrid KEX + X.509 cert: PQC HTTPS)\n' "cert / X509 (PQC KEX)" "$(textsz $OUT/wn_cert_pqc.elf)"
