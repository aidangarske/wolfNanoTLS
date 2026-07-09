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

Percentages are how much **smaller** wolfNanoTLS is than that column.

| Client | wolfNanoTLS | mbedTLS 3.6.0 | mbedTLS 4.1.0 | wolfSSL |
|---|--:|--:|--:|--:|
| PSK + ECDHE, X25519 | **18,680** | 42,100 (56%) | 36,512 (49%) | 48,495 (61%) |
| PSK + ECDHE, P-256 | **26,604** | 50,848 (48%) | 42,284 (37%) | 62,182 (57%) |
| cert / X.509, P-256 | **54,280** | 101,232 (46%) | 70,832 (23%) | 151,829 (64%) |

The cert row uses wolfNanoTLS's native `wn_x509` parser (`WOLFNANO_X509_LITE`,
53.0 KB); the default `asn.c` backend is 63,877 B (62.4 KB), still ~10% under
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
- Full wolfSSL with X.509 is ~150 KB, which is the reason a slim shell exists.

At ~18 KB the X25519 PSK client fits where even a hard-minimized mbedTLS 4.1.0
(36 KB) cannot, and a stock mbedTLS is out of the question. mbedTLS and stock
wolfSSL also ship **no ML-KEM / ML-DSA**, so wolfNanoTLS's PQC client rows have no
counterpart.

## Footprint: whole TLS 1.3 server (Cortex-M33, `.text` bytes)

The `WOLFNANO_SERVER` adder (off by default), built the same way (`-Os -flto
--gc-sections`, ArmGNU 14.2), every library hard-minimized to the same scope.
wolfNanoTLS links only `wn_Accept_*` (no `wn_connect`); wolfSSL is
`NO_WOLFSSL_CLIENT`; mbedTLS keeps only `ssl_tls13_server`. cert rows use the
native `wn_x509` LITE backend; ML-DSA-44 is a post-quantum server signature;
X25519MLKEM768 is a hybrid-PQC key exchange. mbedTLS ships no ML-KEM / ML-DSA, so
those rows are **N/A**.

Every server is a **direct measurement**: fed the captured ClientHello
(`bench/min/*_server_fed.c`, through a `volatile` mask so `-flto` cannot fold it)
and, for cert, a real embedded ECDSA P-256 leaf (`bench/min/srv_cert.h`), so the
full handshake — including the CertVerify sign path — links. A garbage-input
server stub degenerates under `-flto` (the parse fails early and the rest of the
handshake is proved unreachable, collapsing mbedTLS to ~3-11 KB); feeding it is
what makes all three measured the same, honest way. mbedTLS's server ≈ its client
(cert 3.6: 96.8K vs 101.2K; 4.1: 72.6K vs 70.8K) — it builds both roles from one
TLS 1.3 core and barely slims for server-only, whereas wolfNanoTLS's cert server
(46.8K) is 14% under its own client (54.3K) because `wn_accept` (sign) and
`wn_connect` (verify a full chain) are genuinely separate units.

| Server | wolfNanoTLS | mbedTLS 3.6.0 | mbedTLS 4.1.0 | wolfSSL |
|---|--:|--:|--:|--:|
| PSK + ECDHE, X25519 | **20,084** | 42,408 (53%) | 35,932 (44%) | 47,485 (58%) |
| PSK + ECDHE, P-256 | **28,008** | 51,156 (45%) | 41,764 (33%) | 61,166 (54%) |
| cert / X.509, P-256 | **46,768** | 96,822 (52%) | 72,645 (36%) | 152,725 (69%) |
| cert / X.509, ML-DSA-44 | **57,449** | N/A | N/A | 170,577 (66%) |
| PSK, X25519MLKEM768 | **33,128** | N/A | N/A | 67,694 (51%) |

## Footprint: whole TLS 1.3 client+server device (Cortex-M33, `.text` bytes)

The realistic case: one binary that is **both** client and server (wolfNanoTLS
links `wn_Connect_*` + `wn_Accept_*`; wolfSSL neither `NO_WOLFSSL_CLIENT` nor
`NO_WOLFSSL_SERVER`; mbedTLS keeps both `ssl_tls13_client` and `ssl_tls13_server`).
The combined driver drives its client half (which sends first, staying reachable)
and feeds its server half the captured ClientHello + real cert, so both roles link
(`bench/min/*_clientserver_fed.c`).

| Client+server device | wolfNanoTLS | mbedTLS 3.6.0 | mbedTLS 4.1.0 | wolfSSL |
|---|--:|--:|--:|--:|
| PSK + ECDHE, X25519 | **22,612** | 42,384 (47%) | 36,512≈ (38%) | 54,670 (59%) |
| PSK + ECDHE, P-256 | **30,392** | 51,156≈ (41%) | 42,284≈ (28%) | 68,234 (55%) |
| cert / X.509, P-256 | **61,424** | 116,218 (47%) | 73,108 (16%) | 157,522 (61%) |
| cert / X.509, ML-DSA-44 | **77,518** | N/A | N/A | 175,469 (56%) |
| PSK, X25519MLKEM768 | **39,236** | N/A | N/A | 74,792 (48%) |

`≈` = mbedTLS PSK device: its combined size-stub degenerates under `-flto` for the
PSK rows, and mbedTLS's PSK device genuinely equals its client/server (all ~42K /
~51K — shared role code), so those cells use the measured client/server value. The
cert devices are direct measurements.

The cert-device gap vs the very lean mbedTLS 4.1 (16%) is the smallest cell only
because all four carry the full **web-PKI** stack there (RSA + ECDSA + Ed25519
verify). For a real ECDSA-P-256 build the gap doubles — see the P-256-only tier
below.

## Footprint: cert, real P-256-only (Cortex-M33, `.text` bytes)

The cert rows above are full web-PKI (verify RSA + ECDSA + Ed25519, SHA-256/384/512)
for **all four** libraries — the honest number for public HTTPS. For an ECDSA-P-256
private PKI (typical IoT), all four drop RSA + Ed25519 + SHA-384/512. wolfNanoTLS
uses `configs/user_settings_cert_p256min.h` (the `wn_x509` LITE parser recognizes
P-256 + ECDSA-SHA256 only):

| cert, P-256-only | wolfNanoTLS | mbedTLS 3.6.0 | mbedTLS 4.1.0 | wolfSSL |
|---|--:|--:|--:|--:|
| client | **36,552** | 85,152 (57%) | 58,957 (38%) | 85,267 (57%) |
| server | **34,040** | 80,873 (58%) | 60,307 (44%) | 85,961 (60%) |
| client+server device | **43,944** | 101,323 (57%) | 64,167 (32%) | 90,579 (51%) |

Dropping web-PKI sheds ~18K from wolfNanoTLS but only ~9K from mbedTLS 4.1 (its
RSA/SHA live in the shared PSA core), so wolfNanoTLS pulls further ahead — the
device gap vs 4.1 doubles from 16% to **32%**, client/server run 38–44% under 4.1
and 57–60% under 3.6 and wolfSSL. Of the 43,944 P-256 device, ~25K is the
security-critical wolfCrypt floor (ecc + sp_int + SHA + AES + KDF + DRBG, shared
with wolfSSL and constant-time); the ~13K TLS shell is where further wolfNanoTLS
reductions live (tracked in issues #113–#115). mbedTLS 4.1 is markedly leaner than
3.6 because 4.x moved crypto into a PSA-first `tf-psa-crypto` core, dropping 3.6's
dual legacy+PSA code paths.

wolfNanoTLS is roughly **half** of a comparably-scoped mbedTLS 3.6 and a **third**
of a full wolfSSL in every role, and 16-44% under the much leaner mbedTLS 4.1 (more
on the single-role cert client/server, least on the full-web-PKI device — the
P-256-only tier above widens that to 32-44%). It is also the only one of the three
with post-quantum ML-KEM key exchange and ML-DSA server signatures at all (mbedTLS
has neither).

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

**vs wolfSSL, speed is a wash by construction.** wolfNanoTLS calls the exact same
wolfCrypt primitives through the `wc_*` seam and links the same target assembly
(AES-NI/AVX2 on x86_64, the ARMv8/Cortex-M speedups on embedded), so per-operation
crypto throughput is effectively identical to wolfSSL - there is no speed penalty
for the smaller shell. wolfSSL is therefore omitted from the speed table (it would
duplicate the wolfNanoTLS column); the wolfSSL story is purely the size columns
above, where the slim shell is ~3x smaller.

\* mbedTLS's benchmark prints SHA-512 (shares the SHA-384 64-bit core), shown as
the SHA-384 comparator. † mbedTLS 4.1.0's benchmark stubs out ECDH
("to be re-done based on PSA"), so it is not measured there.
