#!/bin/sh
# Live interop: launch openssl s_server (TLS 1.3, external PSK) and run the
# wolfNanoTLS PSK client against it.
set -u
PORT=14433
PSK=000102030405060708090a0b0c0d0e0f
LOG=/tmp/wn_sserver.log

openssl s_server -psk "$PSK" -psk_identity Client_identity -nocert \
    -tls1_3 -accept "$PORT" -quiet >"$LOG" 2>&1 &
SPID=$!

# wait for the listener
i=0
while [ $i -lt 50 ]; do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then break; fi
    sleep 0.1
    i=$((i + 1))
done

./build/interop_psk_client "$PORT"
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
