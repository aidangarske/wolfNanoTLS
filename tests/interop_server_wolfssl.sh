#!/bin/sh
# Live interop: wolfNanoTLS PSK server against the wolfSSL example client (TLS
# 1.3, external PSK). WNGROUP forces the client key-share group to match the
# server build. Skips cleanly when the wolfSSL build has PSK compiled out.
set -u
PORT=15437
SRV=${SERVER:-./build/example_server}
WNGROUP=${WNGROUP:-x25519}
# Prefer a PSK-enabled wolfSSL build if present (the stock ref may be NO_PSK).
if [ -z "${WOLFSSL_DIR:-}" ]; then
    if [ -x "$HOME/wolfssl-psk/examples/client/client" ]; then
        WOLFSSL_DIR=$HOME/wolfssl-psk
    else
        WOLFSSL_DIR=$HOME/wolfssl
    fi
fi
CLI="$WOLFSSL_DIR/examples/client/client"

case "$WNGROUP" in
    x25519) KXFLAG="-t";;                         # X25519 for key exchange
    p256)   KXFLAG="-Y";;                         # ECC named group (secp256r1)
    hybrid) KXFLAG="--pqc X25519MLKEM768";;
    *)      KXFLAG="";;
esac

[ -x "$CLI" ] || { printf "\033[33mSKIP wolfssl server interop (no client at $CLI)\033[0m\n"; exit 0; }
if grep -q "define *NO_PSK" "$WOLFSSL_DIR/wolfssl/options.h" 2>/dev/null; then
    printf "\033[33mSKIP wolfssl server interop (wolfSSL built with NO_PSK)\033[0m\n"; exit 0
fi

# wolfSSL's TLS 1.3 external-PSK client appends the hash to the identity.
"$SRV" "$PORT" Client_identitySHA256 >/tmp/wn_server_ws.log 2>&1 &
SPID=$!
sleep 0.5

( cd "$WOLFSSL_DIR" && exec examples/client/client -v 4 -s $KXFLAG \
    -h 127.0.0.1 -p "$PORT" ) >/tmp/wn_wsclient.log 2>&1

# Never block forever if the client exited before connecting: poll, then reap.
i=0
while [ $i -lt 30 ] && kill -0 "$SPID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
SRC=$?

if grep -q "handshake complete" /tmp/wn_server_ws.log; then
    printf "\033[32mPASS\033[0m TLS 1.3 PSK server (wolfSSL client, $WNGROUP)\n"
    exit 0
fi
printf "\033[31mFAIL wolfssl server interop $WNGROUP (server rc=$SRC)\033[0m\n"
cat /tmp/wn_server_ws.log
exit 1
