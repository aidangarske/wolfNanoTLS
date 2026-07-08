#!/bin/sh
# mbedTLS 4.1.0 TLS 1.3 client+server DEVICE footprint (Cortex-M33, -Os, gc-sections): PSK+ECDHE
# X25519, PSK+ECDHE P-256, and X.509 cert (ECDSA P-256). Server-side of the
# tf-psa-crypto build (keeps both ssl_tls13 client+server). Mirrors footprint-mbedtls4*.sh.
set -u

MB=${MBEDTLS4_DIR:-$HOME/mbedtls-4.1.0}
ARM=${ARM_GNU_BIN:-$(echo /Applications/ArmGNUToolchain/*/arm-none-eabi/bin 2>/dev/null)}
CC=$ARM/arm-none-eabi-gcc
SIZE=$ARM/arm-none-eabi-size
BENCH=$(cd "$(dirname "$0")/min" && pwd)
OUT=${TMPDIR:-/tmp}/wn_mb4_cs
GEN=$OUT/gen

command -v "$CC" >/dev/null 2>&1 || { printf "\033[33mSKIP (no arm-none-eabi-gcc)\033[0m\n"; exit 0; }
[ -d "$MB/tf-psa-crypto" ] || { printf '\033[33mSKIP (no mbedTLS 4.x at %s; set MBEDTLS4_DIR)\033[0m\n' "$MB"; exit 0; }

rm -rf "$OUT"; mkdir -p "$OUT" "$GEN"
PY=python3
if ! python3 -c 'import jsonschema, jinja2' 2>/dev/null; then
    python3 -m venv "$OUT/venv"; "$OUT/venv/bin/pip" install --quiet jsonschema jinja2; PY="$OUT/venv/bin/python"
fi
"$PY" "$MB/tf-psa-crypto/scripts/generate_driver_wrappers.py" "$GEN"

ARCH="-mcpu=cortex-m33 -mthumb"
OPT="-Os -ffunction-sections -fdata-sections -flto"
LINK="-flto -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs"
INC="-I$BENCH -I$MB/include -I$MB/library -I$MB/tf-psa-crypto/include \
 -I$MB/tf-psa-crypto/drivers/builtin/include -I$MB/tf-psa-crypto/drivers/builtin/src \
 -I$MB/tf-psa-crypto/core -I$MB/tf-psa-crypto/extras -I$MB/tf-psa-crypto/utilities \
 -I$MB/tf-psa-crypto/platform -I$MB/tf-psa-crypto/dispatch -I$GEN"
# server build: keep ssl_tls13_server, drop ssl_tls13_client (and the tls12 pair)
EX_COMMON=" net_sockets timing ssl_tls12_client ssl_tls12_server \
 ssl_cache ssl_ticket ssl_cookie pkcs7 x509_crl x509_csr x509_create x509write \
 x509write_crt x509write_csr mbedtls_config debug psa_crypto_storage psa_its_file \
 entropy entropy_poll ctr_drbg hmac_drbg aesni aesce lms lmots nist_kw pkwrite \
 mps_trace base64 pem pkcs5 threading memory_buffer_alloc \
 tf_psa_crypto_config tf_psa_crypto_version version "

build() { # $1=config $2=crypto_config $3=driver $4=out
    d="$OUT/$4"; rm -rf "$d"; mkdir -p "$d"
    DEF="-DMBEDTLS_CONFIG_FILE=\"$1\" -DTF_PSA_CRYPTO_CONFIG_FILE=\"$2\""
    for f in "$MB"/library/*.c "$MB"/tf-psa-crypto/core/*.c \
             "$MB"/tf-psa-crypto/drivers/builtin/src/*.c "$MB"/tf-psa-crypto/extras/*.c \
             "$MB"/tf-psa-crypto/utilities/*.c "$MB"/tf-psa-crypto/platform/*.c; do
        b=$(basename "$f" .c); case "$EX_COMMON" in *" $b "*) continue ;; esac
        $CC $ARCH $OPT $DEF $INC -c "$f" -o "$d/$b.o" 2>/dev/null
    done
    $CC $ARCH $OPT $DEF $INC -c "$GEN/psa_crypto_driver_wrappers_no_static.c" -o "$d/drv.o" 2>/dev/null
    $CC $ARCH $OPT $DEF $INC -c "$BENCH/$3" -o "$d/srv.o" 2>/dev/null
    $CC $ARCH $OPT $LINK "$d"/*.o -o "$d.elf" 2>/dev/null
    "$SIZE" "$d.elf" 2>/dev/null | awk 'NR==2{print $1}'
}

X=$(build mbedtls4_config_psk_cs.h mbedtls4_crypto_config_psk_x25519.h mbed_psk_clientserver4.c psk_x25519)
P=$(build mbedtls4_config_psk_cs.h mbedtls4_crypto_config_psk_p256.h  mbed_psk_clientserver4.c psk_p256)
C=$(build mbedtls4_config_cs.h   mbedtls4_crypto_config.h           mbed_clientserver4.c     cert)

printf '\nmbedTLS 4.1.0 TLS 1.3 client+server DEVICE .text (Cortex-M33, -Os, gc-sections):\n'
printf '  %-24s %s\n' "PSK + ECDHE, X25519" "${X:--}"
printf '  %-24s %s\n' "PSK + ECDHE, P-256"  "${P:--}"
printf '  %-24s %s\n' "cert / X.509, P-256" "${C:--}"
