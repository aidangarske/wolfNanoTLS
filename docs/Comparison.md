# Comparison vs mbedTLS / wolfSSL

wolfNanoTLS's own size and speed numbers live in [Footprint](Footprint.md) and
[Benchmarks](Benchmarks.md). This page is the head-to-head against
hard-minimized / stock mbedTLS and full wolfSSL, for the cases where a
comparison is useful. Reproduce with `sh bench/footprint-clients.sh` (size,
needs an mbedTLS tree at `$MBEDTLS_DIR`) and `make bench` (speed).

## Footprint: whole TLS 1.3 client (Cortex-M33, `.text` bytes)

Linked from source for Cortex-M33 (X25519, AES-128-GCM, SHA-256),
`arm-none-eabi-gcc -Os -flto -ffunction-sections -fdata-sections
-Wl,--gc-sections` + nano specs (ArmGNU 14.2), with wolfNanoTLS and both mbedTLS
releases **hard-minimized to the identical scope**. mbedTLS 4.x is markedly
leaner than 3.6, so it is the tougher comparison; wolfNanoTLS is smaller than
either:

| Client | wolfNanoTLS | mbedTLS 3.6.0 | mbedTLS 4.1.0 | vs 4.1.0 | vs 3.6.0 |
|---|--:|--:|--:|--:|--:|
| PSK + ECDHE, X25519 | **18,680** | 42,100 | 36,512 | 49% | 56% |
| PSK + ECDHE, P-256 | **26,604** | 50,848 | 42,284 | 37% | 48% |
| cert / X.509, P-256 | **54,396** | 101,232 | 70,832 | 23% | 46% |

The cert row uses wolfNanoTLS's native `wn_x509` parser (`WOLFNANO_X509_LITE`,
53.1 KB); the default `asn.c` backend is 63,877 B (62.4 KB), still ~10% under
mbedTLS 4.1.0. For reference, full wolfSSL with X.509 is ~150 KB (150,949 B) -
the reason the slim shell exists. Reproduce the mbedTLS 3.6 row with
`MBEDTLS_DIR=<3.6 tree> sh bench/footprint-clients.sh`, and the 4.1.0 rows with
`sh bench/footprint-mbedtls4.sh` (cert) + `sh bench/footprint-mbedtls4-psk.sh`
(PSK). See [Footprint](Footprint.md).

mbedTLS is given its smallest config too (`MBEDTLS_ECP_FIXED_POINT_OPTIM 0`,
`ECP_WINDOW_SIZE 2`) so the comparison is not inflated in wolfNanoTLS's favor. Both
sides are hard-minimized to **SHA-256 only** (verified: zero SHA-384/512/3, MD5,
SHA-1, DES, ChaCha, CBC/CTR, RSA, ECDSA symbols in either PSK binary). SHA-256
is mandatory in TLS 1.3 (HKDF key schedule, transcript hash, Finished MAC, PSK
binder) and present on both. The remaining gap is architectural: wolfNanoTLS uses
specialized `fe_*` X25519 field arithmetic and direct `wc_*` calls; mbedTLS
routes X25519 through its general ECP + bignum and the mandatory PSA dispatch
layer, and links full AES tables.

The honest framing:

- **Hard-minimized both sides (the fair number): ~49% / 37% (PSK) / 23% (cert)
  smaller.** Getting mbedTLS this small required a custom minimal `PSA_WANT_*`
  crypto config and stripping restartable-ECP, SHA-384/512, and the non-GCM AES
  modes, because mbedTLS's PSA layer pulls in RSA, SHA-1/3, Camellia, DES,
  ChaCha by default.
- **Exact configs:** `bench/min/mbedtls4_config.h` +
  `bench/min/mbedtls4_crypto_config.h` (cert), `bench/min/mbedtls4_config_psk.h`
  + `mbedtls4_crypto_config_psk_*.h` (PSK) for mbedTLS 4.1.0;
  `configs/user_settings_*.h` (wolfNanoTLS).
- **Both harness clients use opaque (volatile) I/O stubs**, so neither side is
  dead-stripped (making the mbedTLS bio opaque too moved its PSK number by
  <30 bytes).
- **Raw crypto primitives are ~parity** (mbedTLS's compact bignum/ECP is its
  design strength); wolfNanoTLS's win is the TLS layer plus whole-stack assembly.
- Full wolfSSL with X.509 is ~147 KB, which is the reason a slim shell exists.

At ~17 KB the X25519 PSK client fits where even a hard-minimized mbedTLS 4.1.0
(36 KB) cannot, and a stock mbedTLS is out of the question. mbedTLS and stock
wolfSSL also ship **no ML-KEM / ML-DSA**, so wolfNanoTLS's PQC client rows have no
counterpart.

## TLS-layer source + `.text` (host clang, `-Os`)

The crypto floor is the same wolfcrypt objects in both, so it is not the
differentiator; the TLS layer is.

| | `__TEXT` bytes | source lines |
|---|--:|--:|
| wolfNanoTLS slim shell (full TLS 1.3 PSK+ECDHE client) | 8,724 | 1,351 |
| wolfSSL TLS layer (`tls13.c` + `tls.c` only) | 52,318 | (subset) |
| wolfSSL `tls13.c`+`tls.c`+`internal.c`+`ssl.c` | n/a | 96,433 |

The complete wolfNanoTLS TLS 1.3 client is roughly 6x smaller in compiled `.text`
than just `tls13.c` + `tls.c`, and omits `internal.c` and `ssl.c` entirely (the
`WOLFSSL` object model), which is the bulk of the wolfSSL TLS-layer size.

## Speed (i7-7920HQ, 1 KB block, hardware acceleration active on all three)

wolfNanoTLS's `intel` build (wolfCrypt Intel asm - AES-NI + AVX2 + SP x86_64 -
through the `wc_*` seam) vs mbedTLS 3.6.0 and 4.1.0, all built AES-NI-on
(`-O2 -march=native`) and measured on the same host, 1 KB block. Acceleration was
verified by cycles/byte on every row (wolfNano AES-GCM ~1 c/B; mbedTLS AES-CTR
4-6 c/B). The old revision of this table accidentally used wolfNanoTLS's
**portable-C** build and an un-accelerated mbedTLS, understating both sides; the
numbers below are the asm/AES-NI figures.

| Operation | wolfNanoTLS | mbedTLS 3.6.0 | mbedTLS 4.1.0 | faster vs 3.6 | vs 4.1 |
|---|--:|--:|--:|--:|--:|
| AES-128-GCM | **2832 MiB/s** | 322 | 262 | 8.8x | 10.8x |
| AES-256-GCM | **2213 MiB/s** | 287 | 230 | 7.7x | 9.6x |
| ChaCha20-Poly1305 | **957 MiB/s** | 260 | 192 | 3.7x | 5.0x |
| SHA-256 | **310 MiB/s** | 225 | 165 | 1.4x | 1.9x |
| SHA-384 | **411 MiB/s** | 272* | 200* | 1.5x | 2.1x |
| ECDSA P-256 sign | **45192 op/s** | 2106 | 1100 | 21x | 41x |
| ECDSA P-256 verify | **17316 op/s** | 441 | 510 | 39x | 34x |
| ECDH P-256 agree | **16114 op/s** | 462 | n/a† | 35x | - |
| RSA-2048 public | **51804 op/s** | 2843 | 6400 | 18x | 8x |
| RSA-2048 private | **1526 op/s** | 251 | 175 | 6.1x | 8.7x |
| ML-KEM-768 keygen | **84102 op/s** | n/a | n/a | - | - |
| ML-KEM-768 encap | **88895 op/s** | n/a | n/a | - | - |
| ML-KEM-768 decap | **60825 op/s** | n/a | n/a | - | - |
| ML-DSA-44 sign | **10341 op/s** | n/a | n/a | - | - |
| ML-DSA-44 verify | **27880 op/s** | n/a | n/a | - | - |

wolfNanoTLS is ~8-11x on AES-GCM, ~4-5x on ChaCha20-Poly1305, ~1.4-2x on SHA-2,
and ~6-41x on public-key ops over both mbedTLS releases - the wolfCrypt Intel
assembly, same as wolfSSL. SHA-2 is software on this Kaby Lake (no SHA-NI, and
mbedTLS has no x86 SHA-NI path at all), so that is where the gap is smallest;
wolfNano's edge there is its AVX2 asm. mbedTLS ships no ML-KEM / ML-DSA (nor
EdDSA), so the post-quantum rows have no counterpart.

\* mbedTLS's benchmark prints SHA-512 (shares the SHA-384 64-bit core), shown as
the SHA-384 comparator. † mbedTLS 4.1.0's benchmark stubs out ECDH
("to be re-done based on PSA"), so it is not measured there.
