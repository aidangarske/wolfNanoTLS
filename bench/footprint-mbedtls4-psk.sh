#!/bin/sh
# mbedTLS 4.x PSK+ECDHE TLS 1.3 client footprint (Cortex-M33). No cert/X.509.
# Usage: build_psk4.sh <crypto_config_header> <out_subdir_name>
set -eu

CRYPTO_CFG=$1
TAG=$2

MB=${MBEDTLS4_DIR:-$HOME/mbedtls-4.1.0}
ARM=${ARM_GNU_BIN:-$(echo /Applications/ArmGNUToolchain/*/arm-none-eabi/bin 2>/dev/null)}
CC=$ARM/arm-none-eabi-gcc
SIZE=$ARM/arm-none-eabi-size
NM=$ARM/arm-none-eabi-nm
BENCH=$(cd "$(dirname "$0")/min" && pwd)
OUT=${TMPDIR:-/tmp}/wn_mb4_psk_$TAG
GEN=$OUT/gen

rm -rf "$OUT"; mkdir -p "$OUT" "$GEN"
PY=python3
if ! python3 -c 'import jsonschema, jinja2' 2>/dev/null; then
    python3 -m venv "$OUT/venv"
    "$OUT/venv/bin/pip" install --quiet jsonschema jinja2
    PY="$OUT/venv/bin/python"
fi
"$PY" "$MB/tf-psa-crypto/scripts/generate_driver_wrappers.py" "$GEN"

ARCH="-mcpu=cortex-m33 -mthumb"
OPT="-Os -ffunction-sections -fdata-sections -flto"
DEF="-DMBEDTLS_CONFIG_FILE=\"mbedtls4_config_psk.h\" -DTF_PSA_CRYPTO_CONFIG_FILE=\"$CRYPTO_CFG\""
INC="-I$BENCH -I$MB/include -I$MB/library -I$MB/tf-psa-crypto/include \
 -I$MB/tf-psa-crypto/drivers/builtin/include -I$MB/tf-psa-crypto/drivers/builtin/src \
 -I$MB/tf-psa-crypto/core -I$MB/tf-psa-crypto/extras -I$MB/tf-psa-crypto/utilities \
 -I$MB/tf-psa-crypto/platform -I$MB/tf-psa-crypto/dispatch -I$GEN"

EXCLUDE=" net_sockets timing ssl_tls12_client ssl_tls12_server ssl_tls13_server \
 ssl_cache ssl_ticket ssl_cookie pkcs7 x509_crl x509_csr x509_create x509write \
 x509write_crt x509write_csr mbedtls_config debug psa_crypto_storage psa_its_file \
 entropy entropy_poll ctr_drbg hmac_drbg aesni aesce lms lmots nist_kw pkwrite \
 mps_trace base64 pem pkcs5 threading memory_buffer_alloc \
 tf_psa_crypto_config tf_psa_crypto_version version "

for f in "$MB"/library/*.c "$MB"/tf-psa-crypto/core/*.c \
         "$MB"/tf-psa-crypto/drivers/builtin/src/*.c "$MB"/tf-psa-crypto/extras/*.c \
         "$MB"/tf-psa-crypto/utilities/*.c "$MB"/tf-psa-crypto/platform/*.c; do
    b=$(basename "$f" .c)
    case "$EXCLUDE" in *" $b "*) continue ;; esac
    $CC $ARCH $OPT $DEF $INC -c "$f" -o "$OUT/$b.o"
done
$CC $ARCH $OPT $DEF $INC -c "$GEN/psa_crypto_driver_wrappers_no_static.c" -o "$OUT/drv.o"
$CC $ARCH $OPT $DEF $INC -c "$BENCH/mbed_psk_client4.c" -o "$OUT/client.o"
$CC $ARCH $OPT -flto -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs \
   "$OUT"/*.o -o "$OUT/mbed_psk_client.elf"

printf '\n=== mbedTLS 4.1.0 TLS 1.3 PSK+ECDHE client [%s] (Cortex-M33, -Os, gc-sections) ===\n' "$TAG"
"$SIZE" "$OUT/mbed_psk_client.elf"
printf 'handshake symbols present:\n'
"$NM" "$OUT/mbed_psk_client.elf" | grep -iE 'ssl_handshake|tls13|ssl_derive|hkdf' | head -20
