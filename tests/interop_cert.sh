#!/bin/sh
# Live interop: openssl s_server with a pinned server cert, wolfNano cert
# client against it. $1 selects the cert type (ecdsa | rsa | ed).
set -u
TYPE=${1:-ecdsa}
PORT=14435
CHAINARG=""
if [ "$TYPE" = "chain" ]; then
    CERT=tests/pki/chain/leaf-cert.pem
    KEY=tests/pki/chain/leaf-key.pem
    ANCHOR=tests/pki/chain/root-cert.der          # pinned root
    CHAINARG="-cert_chain tests/pki/chain/inter-cert.pem"  # send intermediate
else
    CERT=tests/pki/server/$TYPE-cert.pem
    KEY=tests/pki/server/$TYPE-key.pem
    ANCHOR=tests/pki/server/$TYPE-cert.der
fi

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    printf "\033[33mSKIP cert interop ($TYPE cert missing)\033[0m\n"
    exit 0
fi

openssl s_server -cert "$CERT" -key "$KEY" $CHAINARG -tls1_3 -accept "$PORT" \
    -quiet >/tmp/wn_cert_srv.log 2>&1 &
SPID=$!

sleep 1
if ! kill -0 "$SPID" 2>/dev/null; then
    printf "\033[33mSKIP cert interop ($TYPE server did not start)\033[0m\n"
    exit 0
fi

"./build/${WN_CERT_CLIENT:-interop_cert_client}" "$PORT" "$ANCHOR"
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
