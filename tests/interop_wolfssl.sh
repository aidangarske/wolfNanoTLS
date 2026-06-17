#!/bin/sh
# Live interop: wolfNano PSK client against stock wolfSSL's example server.
# The wolfSSL example server uses a fixed TLS 1.3 PSK (01 23 45 67 89 ab cd ef
# repeated) for identity "Client_identity". Skips cleanly if the server binary
# is not present.
set -u
PORT=14434
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SERVER=${WOLFSSL_SERVER:-$HOME/wolfssl/examples/server/server}
WOLFSSL_DIR=$(dirname "$(dirname "$(dirname "$SERVER")")")

if [ ! -x "$SERVER" ]; then
    echo "SKIP wolfSSL interop (server not found at $SERVER)"
    exit 0
fi

( cd "$WOLFSSL_DIR" && "$SERVER" -v 4 -s -p "$PORT" ) >/tmp/wn_wolfssl_srv.log 2>&1 &
SPID=$!

i=0
up=0
while [ $i -lt 50 ]; do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then up=1; break; fi
    sleep 0.1
    i=$((i + 1))
done

if [ "$up" = "0" ]; then
    kill "$SPID" 2>/dev/null
    echo "SKIP wolfSSL interop (server did not start; this wolfSSL build may be"
    echo "     compiled with NO_PSK). Rebuild wolfSSL with PSK enabled, or set"
    echo "     WOLFSSL_SERVER to a PSK-enabled example server."
    exit 0
fi

./build/interop_psk_client "$PORT" "$PSK" Client_identity
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
