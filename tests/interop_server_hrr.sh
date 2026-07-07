#!/bin/sh
# Live interop: force a HelloRetryRequest by making OpenSSL lead with a group
# our single-group server does not have a key_share for (P-256), while still
# offering our group (X25519) in supported_groups. The server must reply with
# HelloRetryRequest (RFC 8446 4.1.4) and complete on ClientHello2. $1 = psk|cert.
set -u
MODE=${1:-psk}
PORT=$([ "${1:-psk}" = "cert" ] && echo 15496 || echo 15495)
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

command -v openssl >/dev/null 2>&1 || {
    printf "\033[33mSKIP HRR interop (no openssl)\033[0m\n"; exit 0; }

if [ "$MODE" = "cert" ]; then
    SRV=${SERVER:-./build/example_server_cert}
    [ -x "$SRV" ] || { printf "\033[33mSKIP HRR cert (server missing)\033[0m\n"; exit 0; }
    "$SRV" "$PORT" tests/pki/server/ec-cert.der tests/pki/server/ec-key-sec1.der \
        0403 >/tmp/wn_hrr_srv.log 2>&1 &
    SPID=$!
    sleep 0.5
    echo "ping" | openssl s_client -tls1_3 -groups P-256:X25519 -msg \
        -connect 127.0.0.1:"$PORT" >/tmp/wn_hrr_cli.log 2>&1
else
    SRV=${SERVER:-./build/example_server}
    [ -x "$SRV" ] || { printf "\033[33mSKIP HRR psk (server missing)\033[0m\n"; exit 0; }
    "$SRV" "$PORT" Client_identity >/tmp/wn_hrr_srv.log 2>&1 &
    SPID=$!
    sleep 0.5
    echo "ping" | openssl s_client -psk "$PSK" -psk_identity Client_identity \
        -tls1_3 -groups P-256:X25519 -msg -connect 127.0.0.1:"$PORT" \
        >/tmp/wn_hrr_cli.log 2>&1
fi

i=0
while [ $i -lt 30 ] && kill -0 "$SPID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null

HELLOS=$(grep -cE "<<< TLS 1.3, Handshake .*ServerHello" /tmp/wn_hrr_cli.log)
if grep -q "handshake complete" /tmp/wn_hrr_srv.log && [ "$HELLOS" -ge 2 ]; then
    printf "\033[32mPASS\033[0m TLS 1.3 HelloRetryRequest ($MODE: HRR + ServerHello, complete)\n"
    exit 0
fi
printf "\033[31mFAIL HRR interop ($MODE: hellos=$HELLOS)\033[0m\n"
cat /tmp/wn_hrr_srv.log; tail -4 /tmp/wn_hrr_cli.log
exit 1
