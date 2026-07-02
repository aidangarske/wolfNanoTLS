#!/bin/sh
# Point the wn_x509 probe example at any live HTTPS endpoints: fetch each host's
# certificate chain with openssl and parse/verify it with build/example_x509_probe,
# surfacing any parse or signature-link errors. Test-oriented - exits non-zero if
# any host's chain fails to parse, so it can run in interop CI.
#
# Usage:  sh examples/x509-probe.sh [host ...]
#         sh examples/x509-probe.sh --list hosts.txt
# With no args, probes a small built-in diverse set.
set -u

PROBE=${PROBE_BIN:-build/example_x509_probe}
WORK=${TMPDIR:-/tmp}/wn_x509_probe
mkdir -p "$WORK"

if [ ! -x "$PROBE" ]; then
    echo "building probe (make example-x509probe) ..."
    make example-x509probe >/dev/null 2>&1 || { echo "build failed"; exit 2; }
fi

if [ "${1:-}" = "--list" ] && [ -n "${2:-}" ]; then
    hosts=$(grep -vE '^\s*#|^\s*$' "$2")
elif [ "$#" -gt 0 ]; then
    hosts="$*"
else
    hosts="cloudflare.com google.com github.com amazon.com apple.com microsoft.com
           letsencrypt.org digicert.com badssl.com ecc256.badssl.com
           ecc384.badssl.com rsa2048.badssl.com rsa4096.badssl.com"
fi

pass=0; fail=0; skip=0; failed=""
for h in $hosts; do
    d="$WORK/$h"; rm -rf "$d"; mkdir -p "$d"
    # retry so a transient blip is not mistaken for a broken/unreachable host
    try=1
    while [ "$try" -le 3 ]; do
        openssl s_client -connect "$h:443" -servername "$h" -showcerts </dev/null \
            2>/dev/null > "$d/chain.pem"
        grep -q "BEGIN CERTIFICATE" "$d/chain.pem" && break
        try=$((try + 1)); [ "$try" -le 3 ] && sleep 3
    done
    # split the PEM bundle into per-cert files, leaf first
    awk -v d="$d" 'BEGIN{n=-1}
        /BEGIN CERTIFICATE/{n++}
        n>=0{print > (d"/c"n".pem")}' "$d/chain.pem"
    ders=""; i=0
    while [ -f "$d/c$i.pem" ]; do
        openssl x509 -inform PEM -outform DER -in "$d/c$i.pem" -out "$d/c$i.der" 2>/dev/null
        ders="$ders $d/c$i.der"
        i=$((i + 1))
    done
    if [ -z "$ders" ]; then
        printf '%-24s SKIP (unreachable after retries)\n' "$h"; skip=$((skip+1)); continue
    fi
    if "$PROBE" $ders >"$d/out.txt" 2>&1; then
        printf '%-24s PASS  %s\n' "$h" "$(grep -m1 '\[0\]' "$d/out.txt" | sed 's/^  //')"
        pass=$((pass+1))
    else
        printf '%-24s FAIL\n' "$h"; sed 's/^/    /' "$d/out.txt"
        fail=$((fail+1)); failed="$failed $h"
    fi
done

echo "----------------------------------------"
echo "probed: $((pass+fail))   pass: $pass   fail: $fail   skip: $skip"
[ -n "$failed" ] && echo "failed:$failed"
[ "$fail" -eq 0 ]
