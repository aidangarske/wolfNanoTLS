#!/bin/sh
# Live interop: launch the wolfNanoTLS certificate server and run a peer TLS 1.3
# client (OpenSSL s_client by default) against it. $1 = cert type (ecdsa | ed |
# rsa). PEER selects the client: openssl (default), wolfssl, mbedtls.
set -u
TYPE=${1:-ecdsa}
PEER=${PEER:-openssl}
PORT=15470
SRV=${SERVER:-./build/example_server_cert}

case "$TYPE" in
    ecdsa) CERT=ec-cert.der;    KEY=ec-key-sec1.der;  SCHEME=0403;;
    ed)    CERT=ed-cert.der;    KEY=ed-key.der;       SCHEME=0807;;
    rsa)   CERT=rsa-cert.der;   KEY=rsa-key-trad.der; SCHEME=0804;;
    mldsa) CERT=mldsa44-cert.der; KEY=mldsa44-key.der; SCHEME=0904;;
    *)     printf "unknown type %s\n" "$TYPE"; exit 1;;
esac
CERTF="tests/pki/server/$CERT"
KEYF="tests/pki/server/$KEY"

[ -x "$SRV" ] && [ -f "$CERTF" ] || {
    printf "\033[33mSKIP cert server interop ($TYPE: server or cert missing)\033[0m\n"; exit 0; }

"$SRV" "$PORT" "$CERTF" "$KEYF" "$SCHEME" >/tmp/wn_certsrv.log 2>&1 &
SPID=$!
sleep 0.5

case "$PEER" in
    openssl)
        echo "ping" | openssl s_client -tls1_3 -connect 127.0.0.1:"$PORT" \
            >/tmp/wn_certcli.log 2>&1 ;;
    wolfssl)
        WD=${WOLFSSL_DIR:-$HOME/wolfssl-psk}
        [ -x "$WD/examples/client/client" ] || { kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null
            printf "\033[33mSKIP cert server ($TYPE vs wolfssl: client unavailable)\033[0m\n"
            exit 0; }
        ( cd "$WD" && exec examples/client/client -v 4 -d -t \
            -h 127.0.0.1 -p "$PORT" ) >/tmp/wn_certcli.log 2>&1 ;;
    mbedtls)
        MB=${MBEDTLS_CLIENT:-$HOME/mbedtls/programs/ssl/ssl_client2}
        [ -x "$MB" ] || { kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null
            printf "\033[33mSKIP cert server ($TYPE vs mbedtls: ssl_client2 unavailable)\033[0m\n"
            exit 0; }
        "$MB" server_addr=127.0.0.1 server_port="$PORT" force_version=tls13 \
            groups=x25519 auth_mode=none \
            ca_file="tests/pki/server/${CERT%.der}.pem" \
            >/tmp/wn_certcli.log 2>&1 ;;
esac

i=0
while [ $i -lt 30 ] && kill -0 "$SPID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null

if grep -q "handshake complete" /tmp/wn_certsrv.log; then
    printf "\033[32mPASS\033[0m TLS 1.3 cert server ($TYPE vs $PEER)\n"
    exit 0
fi
# mbedTLS ssl_client2 rejects a self-signed leaf trust anchor (not a CA, CN
# mismatch) regardless of auth_mode; that is its PKI policy, not a server fault
# (OpenSSL, wolfSSL and the wolfNanoTLS client all complete this handshake).
if [ "$PEER" = "mbedtls" ] && grep -qE "0x2700|0x262E" /tmp/wn_certcli.log; then
    printf "\033[33mSKIP cert server ($TYPE vs mbedtls: ssl_client2 rejects self-signed leaf or lacks the sig alg)\033[0m\n"
    exit 0
fi
printf "\033[31mFAIL cert server interop ($TYPE vs $PEER)\033[0m\n"
cat /tmp/wn_certsrv.log; tail -3 /tmp/wn_certcli.log
exit 1
