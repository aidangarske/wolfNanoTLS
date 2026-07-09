#!/bin/sh
# Whole TLS 1.3 footprint MATRIX: wolfNanoTLS vs mbedTLS 3.6.0 vs wolfSSL, every
# role (client / server / client+server device) x every row, all built from source
# for Cortex-M33 (Thumb2, -Os, --gc-sections) to the same minimal scope. Reports
# .text bytes; static, no run.
#
# NON-LTO on purpose: -flto does whole-program DCE that collapses a garbage-fed
# server stub to nothing (so LTO forced a client-number "proxy" for the mbedTLS
# server/device). Plain -ffunction-sections + --gc-sections keeps every referenced
# function, so each role is measured for real: distinct, monotonic (device >= max
# of client/server), and deterministic (no LTO partition-order wobble).
#
#   sh bench/footprint-matrix.sh
#   ARM_GNU_BIN=... MBEDTLS_DIR=... sh bench/footprint-matrix.sh
#
# Add a row: append one line to the ROWS loop (wn cfg + crypto, ws cfg dirs, mb
# cfgs or N/A). Add an algorithm to a row: extend that row's crypto list.
set -u
ARM=${ARM_GNU_BIN:-$(echo /Applications/ArmGNUToolchain/*/arm-none-eabi/bin 2>/dev/null)}
CC=$ARM/arm-none-eabi-gcc; SIZE=$ARM/arm-none-eabi-size
MB=${MBEDTLS_DIR:-$HOME/mbedtls}
WC=wolfssl/wolfcrypt/src; WS=wolfssl/src
ARCH="-mcpu=cortex-m33 -mthumb"
OPT="-Os -ffunction-sections -fdata-sections"
LINK="-Wl,--gc-sections --specs=nano.specs --specs=nosys.specs"
O=${TMPDIR:-/tmp}/wn_mtx; rm -rf "$O"; mkdir -p "$O"
command -v "$CC" >/dev/null 2>&1 || { printf "\033[33mSKIP (no complete arm-none-eabi-gcc; set ARM_GNU_BIN)\033[0m\n"; exit 0; }
sz(){ v=$("$SIZE" "$1" 2>/dev/null | awk 'NR==2{print $1}'); [ -n "$v" ] && echo "$v" || echo "-"; }
cfg(){ d="$O/wc_$1"; mkdir -p "$d"; cp "configs/user_settings_$1.h" "$d/user_settings.h"; echo "$d"; }
pc(){ for x in $1; do printf '%s/%s.c ' "$WC" "$x"; done; }   # expand crypto names to $WC paths

BASE="wc_port memory error hash random wolfmath logging coding sha256 hmac kdf aes sp_int"

WN_INC="$OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -I. -Iwolfssl -Iinclude/wolfnano -Isrc"
WN_CORE="src/wn_msg.c src/wn_keyschedule.c src/wn_transcript.c src/wn_record.c src/wn_keyshare.c src/wn_serverhello.c src/wn_clienthello.c src/wn_handshake.c"

# wn_build role cfgdir "extradefs" "crypto" "extrashell" cli srv dev out
wn_build(){
  r=$1; ic=$2; xd=$3; cry=$(pc "$4"); xs=$5; dc=$6; ds=$7; dd=$8; out=$9
  case $r in
   client) $CC -I"$ic" $WN_INC $xd $cry $WN_CORE $xs src/wn_connect.c "bench/min/$dc" $LINK -o "$out" >/dev/null 2>&1;;
   server) $CC -I"$ic" $WN_INC -DWOLFNANO_SERVER $xd $cry $WN_CORE $xs src/wn_accept.c "bench/min/$ds" $LINK -o "$out" >/dev/null 2>&1;;
   device) $CC -I"$ic" $WN_INC -DWOLFNANO_SERVER $xd $cry $WN_CORE $xs src/wn_connect.c src/wn_accept.c "bench/min/$dd" $LINK -o "$out" >/dev/null 2>&1;;
  esac; sz "$out"
}
# mb_build config driver out   (recompiles the mbedTLS library per config)
mb_build(){
  [ -d "$MB" ] || { echo "-"; return; }
  cf="$OPT $ARCH -DMBEDTLS_CONFIG_FILE=\"$1\" -Ibench/min -I$MB/include -I$MB/library"
  d="$O/mb"; rm -rf "$d"; mkdir -p "$d"
  for f in "$MB"/library/*.c; do b=$(basename "$f"); [ "$b" = net_sockets.c ] && continue; [ "$b" = timing.c ] && continue
    $CC $cf -c "$f" -o "$d/$b.o" 2>/dev/null; done
  $CC $cf -c "bench/min/$2" -o "$d/drv.o" 2>/dev/null && \
    $CC $OPT $ARCH $LINK $(ls "$d"/*.o | LC_ALL=C sort) -o "$3" >/dev/null 2>&1
  sz "$3"
}
# ws_build cfgdir "crypto-extra" driver out
ws_build(){
  $CC $OPT $ARCH -DWOLFSSL_USER_SETTINGS -DWOLFNANO_TARGET_PORTABLE_C -I"$1" -Iwolfssl \
    $WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/random.c $WC/wolfmath.c \
    $WC/logging.c $WC/coding.c $WC/sha256.c $WC/sha512.c $WC/hmac.c $WC/kdf.c $WC/aes.c \
    $WC/curve25519.c $WC/fe_operations.c $WC/sp_int.c $(pc "$2") \
    $WS/ssl.c $WS/internal.c $WS/tls.c $WS/tls13.c $WS/keys.c $WS/wolfio.c \
    "bench/min/$3" $LINK -o "$4" >/dev/null 2>&1
  sz "$4"
}

RES="$O/res"; : > "$RES"
rec(){ printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RES"; }   # role  rowidx  lib  value

# ---- crypto per row (used for ALL roles of that row: roles differ only in TLS code) ----
CRY_x25519="$BASE curve25519 fe_operations"
CRY_p256="$BASE ecc asn"
CRY_cert="$BASE sha512 curve25519 fe_operations ecc asn rsa ed25519 ge_operations"
CRY_mldsa="$CRY_cert sha3 wc_mldsa"
CRY_mlkem="$CRY_x25519 sha3 wc_mlkem wc_mlkem_poly"
WSX_cert="ecc asn rsa ed25519 ge_operations"

row(){ # idx  role  ->  builds all 3 libs for one (row,role)
  i=$1; r=$2
  case $i in
   1) # PSK + ECDHE, X25519
      rec "$r" 1 wn "$(wn_build $r "$(cfg minimal)" "" "$CRY_x25519" "" wn_psk_client.c wn_psk_server.c wn_psk_clientserver.c "$O/wn1_$r")"
      # PSK server uses the both-roles config (client gc-stripped): the server-only
      # PSK config degenerates (undef CLI_C drops TLS 1.3 PSK-server code mbedTLS
      # needs); mbedTLS shares role code so its PSK server == its client anyway.
      case $r in client) mc=mbedtls_config_psk_hardmin_cli.h md=mbed_psk_client.c;; server) mc=mbedtls_config_psk_hardmin.h md=mbed_psk_server_fed.c;; device) mc=mbedtls_config_psk_hardmin.h md=mbed_psk_clientserver.c;; esac
      rec "$r" 1 mb "$(mb_build $mc $md "$O/mb1_$r")"
      case $r in client) wd=ws_cli_psk dr=ws/ws_psk_client.c;; server) wd=ws_srv_psk dr=ws/ws_psk_server.c;; device) wd=ws_cs_psk dr=ws/ws_psk_clientserver.c;; esac
      rec "$r" 1 ws "$(ws_build bench/min/$wd "ecc asn" $dr "$O/ws1_$r")";;
   2) # PSK + ECDHE, P-256
      rec "$r" 2 wn "$(wn_build $r "$(cfg psk_p256)" "" "$CRY_p256" "" wn_psk_client.c wn_psk_server.c wn_psk_clientserver.c "$O/wn2_$r")"
      case $r in client) mc=mbedtls_config_psk_p256_hardmin_cli.h md=mbed_psk_client.c;; server) mc=mbedtls_config_psk_p256_hardmin.h md=mbed_psk_server_fed.c;; device) mc=mbedtls_config_psk_p256_hardmin.h md=mbed_psk_clientserver.c;; esac
      rec "$r" 2 mb "$(mb_build $mc $md "$O/mb2_$r")"
      case $r in client) wd=ws_cli_psk_p256 dr=ws/ws_psk_client.c;; server) wd=ws_srv_psk_p256 dr=ws/ws_psk_server.c;; device) wd=ws_cs_psk_p256 dr=ws/ws_psk_clientserver.c;; esac
      rec "$r" 2 ws "$(ws_build bench/min/$wd "ecc asn" $dr "$O/ws2_$r")";;
   3) # cert / X.509, P-256
      rec "$r" 3 wn "$(wn_build $r "$(cfg cert)" "-DWOLFNANO_X509 -DWOLFNANO_X509_LITE" "$CRY_cert" "src/wn_x509.c src/wn_servercert.c" wn_client.c wn_server.c wn_clientserver.c "$O/wn3_$r")"
      case $r in client) mc=mbedtls_config_tls.h md=mbed_client.c;; server) mc=mbedtls_config_tls_srv.h md=mbed_server.c;; device) mc=mbedtls_config_tls_cs.h md=mbed_clientserver.c;; esac
      rec "$r" 3 mb "$(mb_build $mc $md "$O/mb3_$r")"
      case $r in client) wd=ws dr=ws/ws_cert_client.c;; server) wd=ws_srv dr=ws/ws_cert_server.c;; device) wd=ws_cs dr=ws/ws_cert_clientserver.c;; esac
      rec "$r" 3 ws "$(ws_build bench/min/$wd "$WSX_cert" $dr "$O/ws3_$r")";;
   4) # cert / X.509, ML-DSA-44  (mbedTLS N/A)
      rec "$r" 4 wn "$(wn_build $r "$(cfg cert_mldsa)" "-DWOLFNANO_X509 -DWOLFNANO_X509_LITE -DWN_FP_SCHEME=0x0904" "$CRY_mldsa" "src/wn_x509.c src/wn_servercert.c" wn_client.c wn_server.c wn_clientserver.c "$O/wn4_$r")"
      rec "$r" 4 mb "N/A"
      case $r in client) wd=ws_cli_mldsa dr=ws/ws_cert_client.c;; server) wd=ws_srv_mldsa dr=ws/ws_cert_server.c;; device) wd=ws_cs_mldsa dr=ws/ws_cert_clientserver.c;; esac
      rec "$r" 4 ws "$(ws_build bench/min/$wd "$WSX_cert sha3 wc_mldsa" $dr "$O/ws4_$r")";;
   5) # PSK, X25519MLKEM768  (mbedTLS N/A)
      rec "$r" 5 wn "$(wn_build $r "$(cfg pqc)" "" "$CRY_mlkem" "src/wn_hybrid.c" wn_psk_client.c wn_psk_server.c wn_psk_clientserver.c "$O/wn5_$r")"
      rec "$r" 5 mb "N/A"
      case $r in client) wd=ws_cli_pqc dr=ws/ws_psk_client.c;; server) wd=ws_srv_pqc dr=ws/ws_psk_server.c;; device) wd=ws_cs_pqc dr=ws/ws_psk_clientserver.c;; esac
      rec "$r" 5 ws "$(ws_build bench/min/$wd "ecc asn sha3 wc_mlkem wc_mlkem_poly" $dr "$O/ws5_$r")";;
  esac
}

for R in client server device; do for I in 1 2 3 4 5; do row $I $R; done; done

lbl(){ case $1 in 1) echo "PSK + ECDHE, X25519";; 2) echo "PSK + ECDHE, P-256";; 3) echo "cert / X.509, P-256";; 4) echo "cert / X.509, ML-DSA-44";; 5) echo "PSK, X25519MLKEM768";; esac; }
get(){ awk -F'\t' -v r="$1" -v i="$2" -v l="$3" '$1==r&&$2==i&&$3==l{print $4}' "$RES"; }
table(){
  printf '\n%s .text (Cortex-M33, -Os, gc-sections, NON-LTO, minimal scope):\n' "$1"
  printf '  %-24s %12s %12s %12s\n' "" wolfNanoTLS "mbedTLS3.6" wolfSSL
  for I in 1 2 3 4 5; do printf '  %-24s %12s %12s %12s\n' "$(lbl $I)" "$(get $2 $I wn)" "$(get $2 $I mb)" "$(get $2 $I ws)"; done
}
table "TLS 1.3 CLIENT" client
table "TLS 1.3 SERVER" server
table "TLS 1.3 client+server DEVICE" device
echo ""
echo "NON-LTO: distinct per role, monotonic (device >= client/server), deterministic."
