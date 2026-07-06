#!/bin/sh
# Live TLS 1.3 handshake matrix: real public HTTPS endpoints x X.509 backend x KEX.
# For each host it pins the top cert the server presents, then runs each client
# build and requires a fully validated handshake (SNI + chain + CertVerify +
# hostname). This exercises the whole cert path against real-world diversity
# (key types, CAs, chain depths, cross-signed roots) - path failures a parse-only
# probe cannot see. Network-dependent: skips cleanly when a host is unreachable.
#
# CORE hosts gate the job (a regression there fails CI). EXTRA hosts are run
# warn-only: they exercise breadth and surface known wolfNanoTLS gaps (large
# RSA-4096 chains, >16-SAN leaves on the LITE parser, servers needing HRR)
# without turning CI red on limitations that are tracked separately.
set -u

BUILD=${BUILD:-./build}
TMP=$(mktemp -d)
FAILED=0

green()  { printf "\033[32m%s\033[0m\n" "$1"; }
red()    { printf "\033[31m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }

# fetch_anchor <host>: pin the top cert the server presents -> $TMP/<host>.der.
# Retries so a transient network blip does not look like a broken endpoint.
fetch_anchor() {
    h=$1; _i=1
    while [ "$_i" -le 3 ]; do
        if echo | openssl s_client -connect "$h:443" -servername "$h" -showcerts \
                >"$TMP/$h.pem" 2>/dev/null \
           && python3 - "$TMP/$h.pem" "$TMP/$h.der" <<'PY'
import re, sys, subprocess
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                   open(sys.argv[1]).read(), re.S)
if not certs:
    sys.exit(1)
open(sys.argv[2] + '.pem', 'w').write(certs[-1])
subprocess.run(['openssl', 'x509', '-in', sys.argv[2] + '.pem',
                '-outform', 'DER', '-out', sys.argv[2]], check=True)
PY
        then
            return 0
        fi
        _i=$((_i + 1)); [ "$_i" -le 3 ] && sleep 3
    done
    return 1
}

# run_one <gating> <host> <client-bin> <label>. Core hosts retry (transient blip
# != breakage); breadth hosts run once (a persistent GAP won't gate anyway).
run_one() {
    gating=$1; host=$2; bin=$3; label=$4
    if [ ! -x "$BUILD/$bin" ] || [ ! -f "$TMP/$host.der" ]; then
        yellow "SKIP  $host [$label]"
        return 0
    fi
    tries=1; [ "$gating" = core ] && tries=3
    _i=1
    while [ "$_i" -le "$tries" ]; do
        if "$BUILD/$bin" "$host" "$TMP/$host.der" 443 >/dev/null 2>&1; then
            green "PASS  $host [$label]"
            return 0
        fi
        _i=$((_i + 1)); [ "$_i" -le "$tries" ] && sleep 3
    done
    if [ "$gating" = core ]; then
        red "FAIL  $host [$label]"
        FAILED=1
    else
        yellow "GAP   $host [$label] (tracked limitation)"
    fi
}

# run_neg <host> <client-bin> <label>: a KNOWN-BAD endpoint - the client MUST
# reject it. Accepting it is a security failure and gates the job.
run_neg() {
    host=$1; bin=$2; label=$3
    if [ ! -x "$BUILD/$bin" ] || [ ! -f "$TMP/$host.der" ]; then
        yellow "SKIP  neg $host [$label]"
        return 0
    fi
    if "$BUILD/$bin" "$host" "$TMP/$host.der" 443 >/dev/null 2>&1; then
        red "FAIL  neg $host [$label] (ACCEPTED a bad cert)"
        FAILED=1
    else
        green "PASS  neg $host [$label] (correctly rejected)"
    fi
}

# Diverse, currently-green: ECDSA P-256 (Google/Cloudflare/GitHub), RSA
# (Let's Encrypt/Apple), multiple CAs + chain depths + cross-signed roots.
CORE="www.google.com cloudflare.com valid-isrgrootx1.letsencrypt.org \
  github.com www.apple.com"
# Breadth that surfaces known gaps (warn-only): more CAs, key types, chain
# depths, RSA-4096 chains, >16-SAN leaves. Amazon's CDN serves variable chains
# per edge; some intermittently trip a handshake limitation on both backends.
EXTRA="www.amazon.com www.microsoft.com en.wikipedia.org www.facebook.com www.netflix.com \
  www.paypal.com stackoverflow.com www.yahoo.com duckduckgo.com \
  rsa2048.badssl.com rsa4096.badssl.com ecc256.badssl.com ecc384.badssl.com \
  sha256.badssl.com sha384.badssl.com sha512.badssl.com 1000-sans.badssl.com"
# Known-bad endpoints the client MUST reject (gating). Only cases that fail on
# time/hostname regardless of the pinned anchor (pinning the served top cert
# would defeat an untrusted-root/self-signed test, so those are excluded).
NEG="expired.badssl.com wrong.host.badssl.com"
# Endpoints that negotiate X25519MLKEM768 (post-quantum hybrid KEX).
HYBRID="www.google.com cloudflare.com"

echo "== core: classical KEX, both X.509 backends (gating) =="
for h in $CORE; do
    fetch_anchor "$h" || { yellow "SKIP  $h (unreachable)"; continue; }
    run_one core "$h" example_client_https      "asn.c"
    run_one core "$h" example_client_https_lite "wn_x509"
done

echo "== core: X25519MLKEM768 hybrid KEX (gating) =="
for h in $HYBRID; do
    [ -f "$TMP/$h.der" ] || fetch_anchor "$h" || { yellow "SKIP  $h"; continue; }
    run_one core "$h" example_client_https_pqc "wn_x509 + X25519MLKEM768"
done

echo "== breadth: warn-only, surfaces tracked gaps =="
for h in $EXTRA; do
    fetch_anchor "$h" || { yellow "SKIP  $h (unreachable)"; continue; }
    run_one extra "$h" example_client_https      "asn.c"
    run_one extra "$h" example_client_https_lite "wn_x509"
done

echo "== negative: known-bad endpoints must be rejected (gating) =="
for h in $NEG; do
    fetch_anchor "$h" || { yellow "SKIP  neg $h (unreachable)"; continue; }
    run_neg "$h" example_client_https      "asn.c"
    run_neg "$h" example_client_https_lite "wn_x509"
done

rm -rf "$TMP"
exit $FAILED
