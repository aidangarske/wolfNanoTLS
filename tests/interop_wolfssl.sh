#!/bin/sh
# Live interop: wolfNanoTLS PSK client against stock wolfSSL's example server.
# The wolfSSL example server uses a fixed TLS 1.3 PSK (01 23 45 67 89 ab cd ef
# repeated) for identity "Client_identity". Skips cleanly if the server binary
# is not present.
set -u
PORT=14434
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# Prefer a PSK-enabled wolfSSL build if present (the stock ref may be NO_PSK).
if [ -z "${WOLFSSL_SERVER:-}" ] && [ -x "$HOME/wolfssl-psk/examples/server/server" ]; then
    WOLFSSL_SERVER=$HOME/wolfssl-psk/examples/server/server
fi
SERVER=${WOLFSSL_SERVER:-$HOME/wolfssl/examples/server/server}
WOLFSSL_DIR=$(dirname "$(dirname "$(dirname "$SERVER")")")

if [ ! -x "$SERVER" ]; then
    printf "\033[33mSKIP wolfSSL interop (server not found at $SERVER)\033[0m\n"
    exit 0
fi

( cd "$WOLFSSL_DIR" && exec "$SERVER" -v 4 -s -i -p "$PORT" ) >/tmp/wn_wolfssl_srv.log 2>&1 &
SPID=$!

sleep 1
if ! kill -0 "$SPID" 2>/dev/null; then
    printf "\033[33mSKIP wolfSSL interop (server not running; this wolfSSL build may be\033[0m\n"
    echo "     compiled with NO_PSK). Rebuild wolfSSL with PSK enabled, or set"
    echo "     WOLFSSL_SERVER to a PSK-enabled example server."
    exit 0
fi

"${CLIENT:-./build/interop_psk_client}" "$PORT" "$PSK" Client_identity
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
