#!/bin/sh
# Live interop: stock wolfSSL example server presenting a pinned server cert,
# wolfNanoTLS cert client against it. $1 selects the cert type (ecdsa | rsa | ed).
set -u
TYPE=${1:-ecdsa}
PORT=14436
SERVER=${WOLFSSL_SERVER:-$HOME/wolfssl/examples/server/server}
WOLFSSL_DIR=$(dirname "$(dirname "$(dirname "$SERVER")")")
if [ "$TYPE" = "chain" ]; then
    CERT="$(pwd)/test-pki/chain/fullchain.pem"     # leaf + intermediate
    KEY="$(pwd)/test-pki/chain/leaf-key.pem"
    ANCHOR="$(pwd)/test-pki/chain/root-cert.der"   # pinned root
else
    CERT="$(pwd)/test-pki/server/$TYPE-cert.pem"
    KEY="$(pwd)/test-pki/server/$TYPE-key.pem"
    ANCHOR="$(pwd)/test-pki/server/$TYPE-cert.der"
fi

if [ ! -x "$SERVER" ] || [ ! -f "$CERT" ]; then
    echo "SKIP wolfSSL cert interop ($TYPE: server or cert not found)"
    exit 0
fi

( cd "$WOLFSSL_DIR" && "$SERVER" -v 4 -c "$CERT" -k "$KEY" -d -i -p "$PORT" ) \
    >/tmp/wn_cert_wssl.log 2>&1 &
SPID=$!

sleep 1
if ! kill -0 "$SPID" 2>/dev/null; then
    echo "SKIP wolfSSL cert interop ($TYPE: server did not start; may lack the"
    echo "     key type). See /tmp/wn_cert_wssl.log"
    exit 0
fi

./build/interop_cert_client "$PORT" "$ANCHOR"
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
