# Benchmarks

`make bench` builds the all-algo benchmark (`tests/bench_all.c`) for the
lightweight portable build (`WOLFNANOTLS_ASM=none`) and the Intel asm build
(`WOLFNANOTLS_ASM=intel`) and prints both, so each speedup is visible. Every algo
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
| ML-DSA-65 sign | 1546 ops/s | 4030 ops/s | ~2.6x |
| ML-DSA-65 verify | 4468 ops/s | 10952 ops/s | ~2.5x |

The big wins are AES-NI (symmetric) and the SP x86_64 asm (public key). These
are wolfSSL's own assembly, linked unchanged under wolfNanoTLS's hand-picked build,
so wolfNanoTLS reaches full wolfSSL asm speed with none of the configure surface.

## What the P-256 numbers fixed

Before wiring the specialized SP backend, ECDH P-256 measured ~65 ops/s: the
floor used generic `WOLFSSL_SP_MATH_ALL` (no specialized SP curve code), so ECC
ran on the slow big-integer path. Enabling `WOLFSSL_HAVE_SP_ECC` + the per-arch
SP file is what lifts it to the thousands.

## Other architectures

`WOLFNANOTLS_ASM=thumb2|aarch64|armv7|riscv64` build the same speedups for those
targets, but they cannot run on an x86_64 host. thumb2 and armv7 cross-compile
from source here; aarch64/riscv64 need a complete toolchain. **Speed numbers for
those require the target silicon** (the Cortex-M33 / STM32H563 is the priority
and uses the DWT cycle counter). See [HANDOFF](HANDOFF.md).

## vs MbedTLS (same host, same 1 KB block)

wolfNanoTLS's `intel` build (= wolfCrypt asm through the seam) vs MbedTLS 3.6.0
stock fast config (AES-NI + `MBEDTLS_HAVE_ASM`, `-O2 -march=native`), both on the
i7-7920HQ, 1 KB block:

| Operation | wolfNanoTLS | MbedTLS | faster |
|---|--:|--:|--:|
| AES-128-GCM | 1682 MiB/s | 119 MiB/s | ~14x |
| AES-256-GCM | 1402 MiB/s | 116 MiB/s | ~12x |
| ChaCha20-Poly1305 | 391 MiB/s | 60 MiB/s | ~6.5x |
| SHA-384 | 255 MiB/s | 78 MiB/s | ~3.3x |
| SHA-256 | 173 MiB/s | 58 MiB/s | ~3.0x |
| ECDSA P-256 verify | 9386 op/s | 130 op/s | ~72x |
| RSA-2048 public | 30427 op/s | 954 op/s | ~32x |
| ECDSA P-256 sign | 20799 op/s | 721 op/s | ~29x |
| ECDH P-256 agree | 9472 op/s | 390 op/s | ~24x |
| RSA-2048 private | 861 op/s | 95 op/s | ~9x |

Plus a full PQC + EdDSA suite MbedTLS does not have at all. The block size
matches MbedTLS's benchmark (1 KB) for a fair symmetric comparison; the internal
table above uses 16 KB (ratio is unaffected since both sides use the same size).

## Method

- Each op runs in a time-bounded loop (~0.3s) and reports MB/s (bulk) or ops/s.
- The bench links `-DWOLFNANOTLS_ALLOW_MALLOC` (a measurement tool, not the
  no-alloc product) so ML-DSA keygen/sign and RSA keygen can run in-process.
- Run it: `make bench`. Footprint comparison: `sh bench/footprint-min.sh`
  (see [Footprint](Footprint.md)).
