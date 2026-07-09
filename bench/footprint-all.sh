#!/bin/sh
# One-shot regenerate of every footprint table (Cortex-M33, .text bytes) for the
# docs/Comparison.md tables: client, server, and client+server device, wolfNanoTLS
# vs mbedTLS 3.6.0 / 4.1.0 vs wolfSSL. Each sub-harness sorts its LTO inputs so the
# numbers are deterministic; wrap any of them in footprint-average.sh to prove it.
#
#   sh bench/footprint-all.sh            # print all tables
#   ARM_GNU_BIN=... MBEDTLS_DIR=... MBEDTLS4_DIR=... sh bench/footprint-all.sh
#
# To add an algorithm/row: add its user_settings (configs/ or bench/min/ws_*),
# a bench/min/*_{client,server}.c driver if the API differs, and one build+print
# line in the matching harness below - then rerun this script.
set -u
D=$(cd "$(dirname "$0")/.." && pwd)
cd "$D" || exit 1

bar() { printf '\n============ %s ============\n' "$1"; }

bar "CLIENT (footprint-clients.sh)"
sh bench/footprint-clients.sh 2>/dev/null | grep -vE 'note:|ld:|warning:'

bar "SERVER (footprint-servers.sh)"
sh bench/footprint-servers.sh 2>/dev/null | grep -vE 'note:|ld:|warning:'

bar "CLIENT+SERVER DEVICE (footprint-serverclient.sh)"
sh bench/footprint-serverclient.sh 2>/dev/null | grep -vE 'note:|ld:|warning:'

bar "mbedTLS 4.1.0 SERVER (footprint-mbedtls4-servers.sh)"
sh bench/footprint-mbedtls4-servers.sh 2>/dev/null | grep -vE 'note:|ld:|warning:|pip|venv|Requirement'

echo ""
echo "Deterministic: rerun any harness via  sh bench/footprint-average.sh <harness> 5"
