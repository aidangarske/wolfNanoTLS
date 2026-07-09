#!/bin/sh
# Live interop: wolfNanoTLS PSK server against mbedTLS's ssl_client2 (TLS 1.3,
# external PSK, psk_ephemeral). WNGROUP forces the client key-share group to
# match the server build. Skips cleanly if ssl_client2 is not built.
set -u
PORT=15436
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SRV=${SERVER:-./build/example_server}
WNGROUP=${WNGROUP:-x25519}
CLI=${MBEDTLS_CLIENT:-$HOME/mbedtls/programs/ssl/ssl_client2}

case "$WNGROUP" in
    x25519) MBGRP=x25519;;
    p256)   MBGRP=secp256r1;;
    hybrid) MBGRP=x25519mlkem768;;
    *)      MBGRP=default;;
esac

[ -x "$CLI" ] || { printf "\033[33mSKIP mbedtls server interop (no ssl_client2 at $CLI)\033[0m\n"; exit 0; }

# Skip groups this mbedTLS build does not know (e.g. no ML-KEM hybrid < 4.x).
if "$CLI" groups="$MBGRP" 2>&1 | grep -qi "unknown group"; then
    printf "\033[33mSKIP mbedtls server interop $WNGROUP (group not in this mbedTLS)\033[0m\n"
    exit 0
fi

"$SRV" "$PORT" >/tmp/wn_server_mb.log 2>&1 &
SPID=$!
sleep 0.5

"$CLI" server_addr=127.0.0.1 server_port="$PORT" force_version=tls13 \
    groups="$MBGRP" tls13_kex_modes=psk_ephemeral psk="$PSK" \
    psk_identity=Client_identity >/tmp/wn_mbclient.log 2>&1

# Do not block forever if the client never connected: poll, then reap.
i=0
while [ $i -lt 30 ] && kill -0 "$SPID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
SRC=$?

if grep -q "handshake complete" /tmp/wn_server_mb.log; then
    printf "\033[32mPASS\033[0m TLS 1.3 PSK server (mbedtls ssl_client2, $WNGROUP)\n"
    exit 0
fi
printf "\033[31mFAIL mbedtls server interop $WNGROUP (server rc=$SRC)\033[0m\n"
cat /tmp/wn_server_mb.log; tail -3 /tmp/wn_mbclient.log
exit 1
