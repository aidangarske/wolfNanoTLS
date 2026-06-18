#!/bin/sh
# Live interop: openssl s_server with a pinned server cert, wolfNanoTLS cert
# client against it. $1 selects the cert type (ecdsa | rsa | ed).
set -u
TYPE=${1:-ecdsa}
PORT=14435
CERT=test-pki/server/$TYPE-cert.pem
KEY=test-pki/server/$TYPE-key.pem
ANCHOR=test-pki/server/$TYPE-cert.der

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "SKIP cert interop ($TYPE cert missing)"
    exit 0
fi

openssl s_server -cert "$CERT" -key "$KEY" -tls1_3 -accept "$PORT" -quiet \
    >/tmp/wn_cert_srv.log 2>&1 &
SPID=$!

sleep 1
if ! kill -0 "$SPID" 2>/dev/null; then
    echo "SKIP cert interop ($TYPE server did not start)"
    exit 0
fi

./build/interop_cert_client "$PORT" "$ANCHOR"
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
