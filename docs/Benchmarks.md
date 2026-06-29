# Benchmarks

`make bench` builds the all-algo benchmark (`tests/bench_all.c`) for the
lightweight portable build (`WOLFNANO_ASM=none`) and the Intel asm build
(`WOLFNANO_ASM=intel`) and prints both, so each speedup is visible. Every algo
runs through the `wc_*` seam; disabled algos print `n/a`.

## Host speedups (Intel Core i7-7920HQ, x86_64, clang `-Os`)

Portable C vs the Intel asm bundle (AES-NI, AVX1/2, SP x86_64 asm, AVX2
ML-KEM/ML-DSA). Time-bounded measurement; absolute numbers vary with load, the
ratios are the signal and track wolfSSL's own published figures.

| Algorithm | PORTABLE_C | Intel asm | speedup |
|---|--:|--:|--:|
| AES-128-GCM | 36.8 MB/s | 2706.7 MB/s | ~74x |
| AES-256-GCM | 35.5 MB/s | 2044.6 MB/s | ~58x |
| ChaCha20-Poly1305 | 232.0 MB/s | 971.2 MB/s | ~4.2x |
| SHA-256 | 120.6 MB/s | 217.1 MB/s | ~1.8x |
| SHA-384 | 174.0 MB/s | 329.5 MB/s | ~1.9x |
| SHA3-256 | 153.6 MB/s | 213.7 MB/s | ~1.4x |
| HMAC-SHA256 | 141.3 MB/s | 228.3 MB/s | ~1.6x |
| ECDSA P-256 sign | 392 ops/s | 26446 ops/s | ~67x |
| ECDSA P-256 verify | 202 ops/s | 10013 ops/s | ~50x |
| ECDH P-256 | 433 ops/s | 10546 ops/s | ~24x |
| ECDH P-384 | 165 ops/s | 2923 ops/s | ~18x |
| RSA-2048 sign | 71 ops/s | 941 ops/s | ~13x |
| RSA-2048 verify | 3934 ops/s | 32231 ops/s | ~8x |
| Ed25519 sign | 16089 ops/s | 50542 ops/s | ~3.1x |
| Ed25519 verify | 4948 ops/s | 15198 ops/s | ~3.1x |
| X25519 | 6308 ops/s | 17836 ops/s | ~2.8x |
| ML-KEM-768 keygen | 17096 ops/s | 49572 ops/s | ~2.9x |
| ML-KEM-768 encap | 14627 ops/s | 52906 ops/s | ~3.6x |
| ML-KEM-768 decap | 12893 ops/s | 38360 ops/s | ~3.0x |
| ML-DSA-44 sign (default) | 3012 ops/s | 6226 ops/s | ~2.1x |
| ML-DSA-44 verify (default) | 9019 ops/s | 17580 ops/s | ~1.9x |
| ML-DSA-65 sign (opt-in) | 1546 ops/s | 4030 ops/s | ~2.6x |
| ML-DSA-65 verify (opt-in) | 4468 ops/s | 10952 ops/s | ~2.5x |

ML-DSA defaults to level 2 (ML-DSA-44), security-balanced with the 128-bit
suite; set `WOLFNANO_MLDSA_LEVEL=3` (65) or `5` (87) when a higher level is
required.

The big wins are AES-NI (symmetric) and the SP x86_64 asm (public key). These
are wolfSSL's own assembly, linked unchanged under wolfNanoTLS's hand-picked build,
so wolfNanoTLS reaches full wolfSSL asm speed with none of the configure surface.

## What the P-256 numbers fixed

Before wiring the specialized SP backend, ECDH P-256 measured ~65 ops/s: the
floor used generic `WOLFSSL_SP_MATH_ALL` (no specialized SP curve code), so ECC
ran on the slow big-integer path. Enabling `WOLFSSL_HAVE_SP_ECC` + the per-arch
SP file is what lifts it to the thousands.

## Other architectures

`WOLFNANO_ASM=thumb2|aarch64|armv7|riscv64` build the same speedups for those
targets, but they cannot run on an x86_64 host. thumb2 and armv7 cross-compile
from source here; aarch64/riscv64 need a complete toolchain. **Speed numbers for
those require the target silicon** (the Cortex-M33 / STM32H563 is the priority
and uses the DWT cycle counter).

## STM32H5 (NUCLEO-H563ZI) on-silicon handshake

First on-device numbers: full TLS 1.3 handshake measured client-side with the
DWT cycle counter on a NUCLEO-H563ZI (Cortex-M33 @ ~64 MHz HSI), running as a
wolfNanoTLS client over the [wolfIP](https://github.com/wolfssl/wolfip) stack
against a wolfSSL example server (PSK and X.509). PSK/PQC use the fast Cortex-M
asm SP; the cert rows use portable-C SP (the `sp_cortexm` asm has a wolfSSL
RSA-verify-only build quirk), which is why they are far slower.

| Profile | DWT cycles | ≈ time | SP backend |
|---|--:|--:|---|
| PSK + ECDHE X25519 | 3,228,564 | ~50 ms | Cortex-M asm |
| PSK + ECDHE P-256 | 5,517,711 | ~86 ms | Cortex-M asm |
| PSK + X25519MLKEM768 (PQC) | 6,227,080 | ~97 ms | Cortex-M asm |
| cert / X.509 P-256 | 258,948,145 | ~4.0 s | portable C |
| cert / X.509 + ML-DSA-44 | 121,944,342 | ~1.9 s | portable C |

`ms = cycles / 64000`. Reproduce via the wolfIP STM32H563 port
(`src/port/stm32h563`, `ENABLE_WOLFNANO=1`). Size for the same builds is in
[Footprint](Footprint.md).

A head-to-head against mbedTLS and stock wolfSSL (speed and size) is in
[Comparison](Comparison.md).

## Method

- Each op runs in a time-bounded loop (~0.3s) and reports MB/s (bulk) or ops/s.
- The bench links `-DWOLFNANO_ALLOW_MALLOC` (a measurement tool, not the
  no-alloc product) so ML-DSA keygen/sign and RSA keygen can run in-process.
- Run it: `make bench`. Footprint comparison: `sh bench/footprint-min.sh`
  (see [Footprint](Footprint.md)).
