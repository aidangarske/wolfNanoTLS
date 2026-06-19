#!/bin/sh
# Live interop: wolfNano PSK client against mbedTLS's ssl_server2 (TLS 1.3,
# external PSK, psk_dhe_ke). Third peer alongside OpenSSL and wolfSSL. Skips
# cleanly if ssl_server2 is not built (set MBEDTLS_SERVER to override the path).
set -u
PORT=14436
PSK=000102030405060708090a0b0c0d0e0f
SRV=${MBEDTLS_SERVER:-$HOME/mbedtls/programs/ssl/ssl_server2}

[ -x "$SRV" ] || { printf "\033[33mSKIP mbedtls interop (no ssl_server2 at $SRV)\033[0m\n"; exit 0; }

"$SRV" server_port="$PORT" force_version=tls13 tls13_kex_modes=psk_ephemeral \
    psk="$PSK" psk_identity=Client_identity >/tmp/wn_mbedtls.log 2>&1 &
SPID=$!

i=0
while [ $i -lt 50 ]; do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then break; fi
    sleep 0.1
    i=$((i + 1))
done

./build/interop_psk_client "$PORT" "$PSK" Client_identity
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null

if [ "$RC" -eq 0 ]; then
    printf "\033[32mPASS\033[0m TLS 1.3 PSK handshake (mbedtls)\n"
else
    printf "\033[31mFAIL mbedtls handshake (rc=$RC)\033[0m\n"
fi
exit "$RC"
