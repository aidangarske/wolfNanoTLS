#!/bin/sh
# Live interop: wolfNanoTLS PSK + X25519MLKEM768 hybrid client against stock
# wolfSSL's example server (built with ML-KEM + PSK + curve25519). The wolfNanoTLS
# client offers only the hybrid group, so the server must select it. Skips
# cleanly if the server binary is missing or lacks ML-KEM/PSK.
set -u
PORT=14436
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# A wolfSSL built with --enable-mlkem (standardized X25519MLKEM768). Falls back
# to WOLFSSL_SERVER, then a local checkout; skips cleanly if none supports it.
if [ -z "${WOLFSSL_PQC_SERVER:-}" ] && [ -z "${WOLFSSL_SERVER:-}" ] && \
   [ -x "$HOME/wolfssl-psk/examples/server/server" ]; then
    WOLFSSL_SERVER=$HOME/wolfssl-psk/examples/server/server
fi
SERVER=${WOLFSSL_PQC_SERVER:-${WOLFSSL_SERVER:-$HOME/wolfssl/examples/server/server}}
WOLFSSL_DIR=$(dirname "$(dirname "$(dirname "$SERVER")")")

if [ ! -x "$SERVER" ]; then
    printf "\033[33mSKIP wolfSSL hybrid interop (server not found at $SERVER)\033[0m\n"
    exit 0
fi

( cd "$WOLFSSL_DIR" && exec "$SERVER" -v 4 -s -i -p "$PORT" \
    --pqc X25519MLKEM768 ) >/tmp/wn_wolfssl_hyb_srv.log 2>&1 &
SPID=$!

sleep 2
if ! kill -0 "$SPID" 2>/dev/null; then
    printf "\033[33mSKIP wolfSSL hybrid interop (server not running; this wolfSSL\033[0m\n"
    echo "     build may lack ML-KEM or PSK). Rebuild wolfSSL with --enable-mlkem"
    echo "     --enable-psk --enable-curve25519."
    exit 0
fi

"${CLIENT:-./build/interop_psk_hybrid_client}" "$PORT" "$PSK" Client_identity
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
