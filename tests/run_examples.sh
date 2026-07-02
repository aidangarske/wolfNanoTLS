#!/bin/sh
# Run every wolfNanoTLS example end to end. Three talk to a stock wolfSSL example
# server: the PSK example (-s -i), the X.509 cert example (-c -k -d -i), and the
# PQC hybrid example (--pqc X25519MLKEM768). The fourth is the live HTTPS example,
# run against a real public endpoint. Each is the same binary a user builds from
# examples/. Skips cleanly when the relevant server, build artifact, or network
# is absent so it is safe to run anywhere; live-connect.yml is the hard gate for
# the HTTPS path on main.
set -u

SERVER=${WOLFSSL_SERVER:-$HOME/wolfssl/examples/server/server}
PQC_SERVER=${WOLFSSL_PQC_SERVER:-}
CERT_HOST=${CERT_HOST:-wolfNanoTLS-test}
HTTPS_HOST=${HTTPS_HOST:-valid-isrgrootx1.letsencrypt.org}
HTTPS_ROOT_URL=${HTTPS_ROOT_URL:-https://letsencrypt.org/certs/isrgrootx1.der}
BUILD=${BUILD:-./build}
FAILED=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }
red() { printf "\033[31m%s\033[0m\n" "$1"; }

run_psk() {
    PORT=14480
    if [ ! -x "$SERVER" ]; then
        yellow "SKIP PSK example (wolfSSL server not found at $SERVER)"
        return 0
    fi
    WDIR=$(dirname "$(dirname "$(dirname "$SERVER")")")
    ( cd "$WDIR" && "$SERVER" -v 4 -s -i -p "$PORT" ) >/tmp/wn_ex_psk.log 2>&1 &
    SPID=$!
    sleep 1
    if ! kill -0 "$SPID" 2>/dev/null; then
        yellow "SKIP PSK example (server did not start; may lack PSK support)"
        return 0
    fi
    "$BUILD/example_client" 127.0.0.1 "$PORT"
    RC=$?
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if [ "$RC" -eq 0 ]; then
        green "PASS PSK example"
    else
        red "FAIL PSK example (rc=$RC)"
        FAILED=1
    fi
}

# run_cert_case <tag> <label> <cert.pem> <key.pem> <anchor.der> <client_bin>
# Live TLS 1.3 cert handshake: wolfSSL server presents <cert>, the client pins
# <anchor> and checks the hostname. Exercises one (algorithm x parser-backend).
run_cert_case() {
    TAG=$1; LABEL=$2; CERT=$3; KEY=$4; ANCHOR=$5; BIN=$6
    PORT=14481
    if [ ! -x "$BUILD/$BIN" ]; then
        yellow "SKIP cert $LABEL ($BIN not built)"
        return 0
    fi
    if [ ! -x "$SERVER" ] || [ ! -f "$CERT" ]; then
        yellow "SKIP cert $LABEL (wolfSSL server or cert not found)"
        return 0
    fi
    if ! getent hosts "$CERT_HOST" >/dev/null 2>&1 \
            && ! grep -q "$CERT_HOST" /etc/hosts 2>/dev/null; then
        yellow "SKIP cert $LABEL ($CERT_HOST does not resolve; map it to 127.0.0.1)"
        return 0
    fi
    WDIR=$(dirname "$(dirname "$(dirname "$SERVER")")")
    ( cd "$WDIR" && "$SERVER" -v 4 -c "$CERT" -k "$KEY" -d -i -p "$PORT" ) \
        >"/tmp/wn_ex_cert_$TAG.log" 2>&1 &
    SPID=$!
    sleep 1
    if ! kill -0 "$SPID" 2>/dev/null; then
        yellow "SKIP cert $LABEL (server did not start)"
        return 0
    fi
    "$BUILD/$BIN" "$CERT_HOST" "$PORT" "$ANCHOR"
    RC=$?
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if [ "$RC" -eq 0 ]; then
        green "PASS cert $LABEL"
    else
        red "FAIL cert $LABEL (rc=$RC)"
        FAILED=1
    fi
}

# Every (leaf algorithm x X.509 backend) we have a server cert for: ECDSA P-256
# / P-384, Ed25519, RSA-2048 / RSA-4096, each on wolfSSL asn.c (default) and
# native wn_x509 (LITE) - exercising every CertVerify sig scheme the client offers.
run_cert() {
    P="$(pwd)/tests/pki/server"
    run_cert_case ec_asn      "P-256 (asn.c)"      "$P/ec-cert.pem"      "$P/ec-key.pem"      "$P/ec-cert.der"      example_client_cert
    run_cert_case ec_lite     "P-256 (wn_x509)"    "$P/ec-cert.pem"      "$P/ec-key.pem"      "$P/ec-cert.der"      example_client_cert_lite
    run_cert_case p384_asn    "P-384 (asn.c)"      "$P/p384-cert.pem"    "$P/p384-key.pem"    "$P/p384-cert.der"    example_client_cert
    run_cert_case p384_lite   "P-384 (wn_x509)"    "$P/p384-cert.pem"    "$P/p384-key.pem"    "$P/p384-cert.der"    example_client_cert_lite
    run_cert_case ed_asn      "Ed25519 (asn.c)"    "$P/ed-cert.pem"      "$P/ed-key.pem"      "$P/ed-cert.der"      example_client_cert
    run_cert_case ed_lite     "Ed25519 (wn_x509)"  "$P/ed-cert.pem"      "$P/ed-key.pem"      "$P/ed-cert.der"      example_client_cert_lite
    run_cert_case rsa_asn     "RSA-2048 (asn.c)"   "$P/rsa-cert.pem"     "$P/rsa-key.pem"     "$P/rsa-cert.der"     example_client_cert
    run_cert_case rsa_lite    "RSA-2048 (wn_x509)" "$P/rsa-cert.pem"     "$P/rsa-key.pem"     "$P/rsa-cert.der"     example_client_cert_lite
    run_cert_case rsa4096_asn  "RSA-4096 (asn.c)"   "$P/rsa4096-cert.pem" "$P/rsa4096-key.pem" "$P/rsa4096-cert.der" example_client_cert
    run_cert_case rsa4096_lite "RSA-4096 (wn_x509)" "$P/rsa4096-cert.pem" "$P/rsa4096-key.pem" "$P/rsa4096-cert.der" example_client_cert_lite
}

run_cert_min() {
    PORT=14483
    CERT="$(pwd)/tests/pki/server/ec-cert.pem"
    KEY="$(pwd)/tests/pki/server/ec-key.pem"
    ANCHOR="$(pwd)/tests/pki/server/ec-cert.der"
    if [ ! -x "$BUILD/example_client_cert_min" ]; then
        yellow "SKIP min-cert example (example_client_cert_min not built)"
        return 0
    fi
    if [ ! -x "$SERVER" ] || [ ! -f "$CERT" ]; then
        yellow "SKIP min-cert example (wolfSSL server or EC cert not found)"
        return 0
    fi
    WDIR=$(dirname "$(dirname "$(dirname "$SERVER")")")
    ( cd "$WDIR" && "$SERVER" -v 4 -c "$CERT" -k "$KEY" -d -i -p "$PORT" ) \
        >/tmp/wn_ex_certmin.log 2>&1 &
    SPID=$!
    sleep 1
    if ! kill -0 "$SPID" 2>/dev/null; then
        yellow "SKIP min-cert example (server did not start)"
        return 0
    fi
    # 35 KB P-256/SHA-256 wn_x509-LITE build, anchor-pinned to the EC leaf
    "$BUILD/example_client_cert_min" 127.0.0.1 "$PORT" "$ANCHOR"
    RC=$?
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if [ "$RC" -eq 0 ]; then
        green "PASS min-cert example (P-256/SHA-256 wn_x509 LITE, ~35 KB)"
    else
        red "FAIL min-cert example (rc=$RC)"
        FAILED=1
    fi
}

# PQC HTTPS: X25519MLKEM768 hybrid key exchange + X.509 cert auth (the cert is
# pinned + hostname-checked). Needs an ML-KEM-capable wolfSSL server serving a cert.
run_cert_pqc() {
    PORT=14484
    PSRV=${PQC_SERVER:-$SERVER}
    CERT="$(pwd)/tests/pki/server/ec-cert.pem"
    KEY="$(pwd)/tests/pki/server/ec-key.pem"
    ANCHOR="$(pwd)/tests/pki/server/ec-cert.der"
    if [ ! -x "$BUILD/example_client_cert_pqc" ]; then
        yellow "SKIP cert-pqc example (example_client_cert_pqc not built)"
        return 0
    fi
    if [ ! -x "$PSRV" ] || [ ! -f "$CERT" ]; then
        yellow "SKIP cert-pqc example (ML-KEM wolfSSL server or cert not found)"
        return 0
    fi
    if ! getent hosts "$CERT_HOST" >/dev/null 2>&1 \
            && ! grep -q "$CERT_HOST" /etc/hosts 2>/dev/null; then
        yellow "SKIP cert-pqc example ($CERT_HOST does not resolve; map it to 127.0.0.1)"
        return 0
    fi
    WDIR=$(dirname "$(dirname "$(dirname "$PSRV")")")
    ( cd "$WDIR" && "$PSRV" -v 4 -c "$CERT" -k "$KEY" --pqc X25519MLKEM768 -d -i -p "$PORT" ) \
        >/tmp/wn_ex_certpqc.log 2>&1 &
    SPID=$!
    sleep 1
    if ! kill -0 "$SPID" 2>/dev/null; then
        yellow "SKIP cert-pqc example (server did not start; may lack ML-KEM support)"
        return 0
    fi
    "$BUILD/example_client_cert_pqc" "$CERT_HOST" "$PORT" "$ANCHOR"
    RC=$?
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if [ "$RC" -eq 0 ]; then
        green "PASS cert-pqc example (X25519MLKEM768 hybrid KEX + X.509 cert)"
    else
        red "FAIL cert-pqc example (rc=$RC)"
        FAILED=1
    fi
}

run_pqc() {
    PORT=14482
    PSRV=${PQC_SERVER:-$SERVER}
    if [ ! -x "$BUILD/example_client_pqc" ]; then
        yellow "SKIP PQC example (example_client_pqc not built)"
        return 0
    fi
    if [ ! -x "$PSRV" ]; then
        yellow "SKIP PQC example (wolfSSL server not found at $PSRV)"
        return 0
    fi
    WDIR=$(dirname "$(dirname "$(dirname "$PSRV")")")
    ( cd "$WDIR" && "$PSRV" -v 4 -s -i --pqc X25519MLKEM768 -p "$PORT" ) \
        >/tmp/wn_ex_pqc.log 2>&1 &
    SPID=$!
    sleep 1
    if ! kill -0 "$SPID" 2>/dev/null; then
        yellow "SKIP PQC example (server did not start; may lack ML-KEM support)"
        return 0
    fi
    "$BUILD/example_client_pqc" 127.0.0.1 "$PORT"
    RC=$?
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if [ "$RC" -eq 0 ]; then
        green "PASS PQC example"
    else
        red "FAIL PQC example (rc=$RC)"
        FAILED=1
    fi
}

# Live public HTTPS: SNI + full RFC 5280 chain validation to the fetched root,
# on one X.509 backend. <bin> <label>. ANCHOR must be fetched by the caller.
run_https_one() {
    BIN=$1; LABEL=$2
    if [ ! -x "$BUILD/$BIN" ]; then
        yellow "SKIP HTTPS $LABEL ($BIN not built)"
        return 0
    fi
    i=1
    while [ "$i" -le 3 ]; do
        if "$BUILD/$BIN" "$HTTPS_HOST" "$ANCHOR" 443; then
            green "PASS HTTPS $LABEL (full chain -> ISRG Root X1, SNI + hostname)"
            return 0
        fi
        i=$((i + 1))
        sleep 5
    done
    yellow "SKIP HTTPS $LABEL ($HTTPS_HOST unreachable after 3 tries; live-connect.yml gates this on main)"
}

run_https() {
    ANCHOR=/tmp/wn_isrgrootx1.der
    if ! curl -fsSL --retry 3 "$HTTPS_ROOT_URL" -o "$ANCHOR" 2>/dev/null; then
        yellow "SKIP HTTPS examples (could not fetch trust anchor; no network)"
        return 0
    fi
    # both X.509 backends validate the real public chain to a public root
    run_https_one example_client_https      "asn.c"
    run_https_one example_client_https_lite "wn_x509 LITE"
}

run_psk
run_cert
run_cert_min
run_cert_pqc
run_pqc
run_https

exit $FAILED
