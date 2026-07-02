#!/bin/sh
# mbedTLS 4.x whole-client footprint for the Comparison table: a bare-metal
# Cortex-M33 TLS 1.3 client, same minimal scope as the wolfNanoTLS cert row.
# mbedTLS 4.x split crypto into tf-psa-crypto and needs generated PSA driver
# wrappers (python jsonschema+jinja2), so this is separate from the 3.6 path in
# footprint-clients.sh. Reports .text bytes. Static, no run.
set -eu

MB=${MBEDTLS4_DIR:-$HOME/mbedtls-4.1.0}
ARM=${ARM_GNU_BIN:-$(echo /Applications/ArmGNUToolchain/*/arm-none-eabi/bin 2>/dev/null)}
CC=$ARM/arm-none-eabi-gcc
SIZE=$ARM/arm-none-eabi-size
BENCH=$(cd "$(dirname "$0")/min" && pwd)
OUT=${TMPDIR:-/tmp}/wn_mb4
GEN=$OUT/gen

command -v "$CC" >/dev/null 2>&1 || { printf '\033[33mSKIP (no arm-none-eabi-gcc; set ARM_GNU_BIN)\033[0m\n'; exit 0; }
[ -d "$MB/tf-psa-crypto" ] || { printf '\033[33mSKIP (no mbedTLS 4.x at %s; set MBEDTLS4_DIR)\033[0m\n' "$MB"; exit 0; }

rm -rf "$OUT"; mkdir -p "$OUT" "$GEN"
# mbedTLS 4.x generates PSA driver wrappers via a python tool (jsonschema+jinja2);
# use a throwaway venv so the host python stays untouched (PEP 668 safe).
PY=python3
if ! python3 -c 'import jsonschema, jinja2' 2>/dev/null; then
    python3 -m venv "$OUT/venv"
    "$OUT/venv/bin/pip" install --quiet jsonschema jinja2
    PY="$OUT/venv/bin/python"
fi
"$PY" "$MB/tf-psa-crypto/scripts/generate_driver_wrappers.py" "$GEN"

ARCH="-mcpu=cortex-m33 -mthumb"
OPT="-Os -ffunction-sections -fdata-sections -flto"
DEF="-DMBEDTLS_CONFIG_FILE=\"mbedtls4_config.h\" -DTF_PSA_CRYPTO_CONFIG_FILE=\"mbedtls4_crypto_config.h\""
INC="-I$BENCH -I$MB/include -I$MB/library -I$MB/tf-psa-crypto/include \
 -I$MB/tf-psa-crypto/drivers/builtin/include -I$MB/tf-psa-crypto/drivers/builtin/src \
 -I$MB/tf-psa-crypto/core -I$MB/tf-psa-crypto/extras -I$MB/tf-psa-crypto/utilities \
 -I$MB/tf-psa-crypto/platform -I$MB/tf-psa-crypto/dispatch -I$GEN"

# host-only, out-of-scope for a TLS 1.3 client, or replaced by the external RNG
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
$CC $ARCH $OPT $DEF $INC -c "$BENCH/mbed_client4.c" -o "$OUT/client.o"
$CC $ARCH $OPT -flto -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs \
   "$OUT"/*.o -o "$OUT/mbed_client.elf"

printf 'mbedTLS 4.x TLS 1.3 client .text (Cortex-M33, -Os, gc-sections, minimal scope):\n'
"$SIZE" "$OUT/mbed_client.elf"
