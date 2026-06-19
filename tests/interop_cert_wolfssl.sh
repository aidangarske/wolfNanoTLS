#!/bin/sh
# Live interop: stock wolfSSL example server presenting a pinned server cert,
# wolfNano cert client against it. $1 selects the cert type (ecdsa | rsa | ed).
set -u
TYPE=${1:-ecdsa}
PORT=14436
SERVER=${WOLFSSL_SERVER:-$HOME/wolfssl/examples/server/server}
WOLFSSL_DIR=$(dirname "$(dirname "$(dirname "$SERVER")")")
if [ "$TYPE" = "chain" ]; then
    CERT="$(pwd)/tests/pki/chain/fullchain.pem"     # leaf + intermediate
    KEY="$(pwd)/tests/pki/chain/leaf-key.pem"
    ANCHOR="$(pwd)/tests/pki/chain/root-cert.der"   # pinned root
else
    CERT="$(pwd)/tests/pki/server/$TYPE-cert.pem"
    KEY="$(pwd)/tests/pki/server/$TYPE-key.pem"
    ANCHOR="$(pwd)/tests/pki/server/$TYPE-cert.der"
fi

if [ ! -x "$SERVER" ] || [ ! -f "$CERT" ]; then
    printf "\033[33mSKIP wolfSSL cert interop ($TYPE: server or cert not found)\033[0m\n"
    exit 0
fi

( cd "$WOLFSSL_DIR" && "$SERVER" -v 4 -c "$CERT" -k "$KEY" -d -i -p "$PORT" ) \
    >/tmp/wn_cert_wssl.log 2>&1 &
SPID=$!

sleep 1
if ! kill -0 "$SPID" 2>/dev/null; then
    printf "\033[33mSKIP wolfSSL cert interop ($TYPE: server did not start; may lack the\033[0m\n"
    echo "     key type). See /tmp/wn_cert_wssl.log"
    exit 0
fi

"./build/${WN_CERT_CLIENT:-interop_cert_client}" "$PORT" "$ANCHOR"
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
