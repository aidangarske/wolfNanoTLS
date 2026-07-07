#!/bin/sh
# Live interop: launch the wolfNanoTLS PSK server and run a peer TLS 1.3 client
# (OpenSSL s_client by default) against it. SERVER selects the group build.
set -u
PORT=15433
PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SRV=${SERVER:-./build/example_server}
# Note: KXGROUP, not GROUPS - GROUPS is a reserved shell variable.
KXGROUP=${KXGROUP:-X25519}

# The server example accepts exactly one connection, so probe with a real client
# (a port-scan probe would consume that single accept). Just wait for the bind.
"$SRV" "$PORT" >/tmp/wn_server.log 2>&1 &
SPID=$!
sleep 0.5

# Skip cleanly if this OpenSSL cannot advertise the requested group.
if echo | openssl s_client -groups "$KXGROUP" -connect 127.0.0.1:1 2>&1 \
        | grep -qi "unable to set\|unsupported group\|invalid"; then
    kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null
    printf "\033[33mSKIP openssl server interop ($KXGROUP not supported)\033[0m\n"
    exit 0
fi

echo "ping" | openssl s_client -psk "$PSK" -psk_identity Client_identity \
    -tls1_3 -groups "$KXGROUP" -connect 127.0.0.1:"$PORT" >/tmp/wn_sclient.log 2>&1
CRC=$?

# Never block forever if the client never connected: poll, then reap.
i=0
while [ $i -lt 30 ] && kill -0 "$SPID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
SRC=$?

if grep -q "handshake complete" /tmp/wn_server.log; then
    printf "\033[32mPASS\033[0m TLS 1.3 PSK server (openssl s_client)\n"
    exit 0
fi
printf "\033[31mFAIL server interop (server rc=$SRC client rc=$CRC)\033[0m\n"
cat /tmp/wn_server.log
exit 1
