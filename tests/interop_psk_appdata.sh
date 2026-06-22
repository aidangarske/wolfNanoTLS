#!/bin/sh
# Live app-data interop: openssl s_server in -rev echo mode (TLS 1.3, external
# PSK); the wolfNanoTLS client completes the handshake then sends a line and reads
# the reversed echo back through wn_Send / wn_Recv, then closes.
set -u
PORT=14439
PSK=000102030405060708090a0b0c0d0e0f
LOG=/tmp/wn_sserver_appdata.log

openssl s_server -psk "$PSK" -psk_identity Client_identity -nocert \
    -tls1_3 -accept "$PORT" -rev -quiet >"$LOG" 2>&1 &
SPID=$!

i=0
while [ $i -lt 50 ]; do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then break; fi
    sleep 0.1
    i=$((i + 1))
done

WN_APPDATA=1 "${CLIENT:-./build/interop_psk_client}" "$PORT"
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
