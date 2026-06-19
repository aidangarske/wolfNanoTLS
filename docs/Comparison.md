# wolfNano vs MbedTLS

An apples-to-apples crypto benchmark, modeled on the wolfSSL vs MbedTLS
technical benchmark. wolfNano links wolfCrypt's assembly through the `wc_*`
seam, so this is wolfCrypt's speed delivered from wolfNano's slim, no-configure
build. Both libraries built from source on the same machine and measured the
same way.

**Scope:** Intel x86_64 is measured here. The ARM (Raspberry Pi / Cortex-A) and
bare-metal STM32H563 (Cortex-M33) rows require target hardware and are part of
the device handoff (see [HANDOFF](HANDOFF.md)); the wolfSSL vs MbedTLS document
covers those platforms.

## Method

- **wolfNano:** `WOLFNANO_ASM=intel` (AES-NI, AVX1/2, single-precision x86_64
  assembly, AVX2 ML-KEM/ML-DSA), via `make bench`.
- **MbedTLS 3.6.0:** stock fastest config (`MBEDTLS_HAVE_ASM` + `MBEDTLS_AESNI_C`),
  `-O2 -march=native`, its `programs/test/benchmark`.
- Same host: Intel Core i7-7920HQ (Kaby Lake), x86_64, clang `-Os`/`-O2`.
- Block size 1024 B; symmetric in MiB/s, public-key in operations/s.

> Note: this host is an i7-7920HQ, older than the i9-11950H in the wolfSSL vs
> MbedTLS paper, so absolute numbers are lower on both sides; the ratios are the
> signal and track the paper.

## Symmetric throughput (MiB/s)

| Operation | wolfNano | MbedTLS | Advantage |
|---|--:|--:|--:|
| AES-128-GCM | 1682 | 119 | **14.1x** |
| AES-256-GCM | 1402 | 116 | **12.1x** |
| ChaCha20-Poly1305 | 391 | 60 | **6.5x** |
| SHA-384 | 255 | 78 \* | 3.3x |
| SHA-256 | 173 | 58 | 3.0x |

\* MbedTLS's benchmark reports SHA-512, not SHA-384; they share the same core and
run at the same speed, so it is the fair SHA-384 comparison.

The AES-GCM gap is wolfCrypt's AES-NI + carry-less-multiply GHASH vs a
table-based GCM; the rest is AVX hashing.

## Public-key (operations/s)

| Operation | wolfNano | MbedTLS | Advantage |
|---|--:|--:|--:|
| ECDSA P-256 verify | 9386 | 130 | **72.2x** |
| RSA-2048 public | 30427 | 954 | **31.9x** |
| ECDSA P-256 sign | 20799 | 721 | **28.8x** |
| ECDH P-256 agree | 9472 | 390 \* | **24.3x** |
| ECDH P-384 agree | 2458 | 245 \* | 10.0x |
| RSA-2048 private | 861 | 95 | 9.1x |

\* MbedTLS reports an ECDHE ephemeral handshake (keygen + agree); same pairing as
the wolfSSL vs MbedTLS paper.

Single-precision x86_64 assembly vs portable C, up to ~72x on ECDSA verify.

## Coverage MbedTLS does not have

The same speed-tuned wolfNano build also ships algorithms MbedTLS lacks
entirely. Measured here (wolfNano `intel`, ops/s; MbedTLS: none):

| Operation | wolfNano | MbedTLS |
|---|--:|:--:|
| ML-KEM-768 keygen / encap / decap | 50538 / 51803 / 43259 | none |
| ML-DSA-65 sign / verify | 4734 / 12292 | none |
| Ed25519 sign / verify | 44337 / 14631 | none (no EdDSA signatures) |
| X25519 | 18010 | (ECDH only) |

A complete post-quantum suite (ML-KEM FIPS 203, ML-DSA FIPS 204) plus EdDSA,
none of which MbedTLS provides.

## Reproduce

```sh
# wolfNano (this repo)
make bench                       # none vs intel, all algos
# MbedTLS (3.6.0 at ~/mbedtls)
cd ~/mbedtls && make CFLAGS="-O2 -march=native" -C programs test/benchmark
./programs/test/benchmark aes_gcm sha256 sha512 chachapoly ecdsa ecdh rsa
```

## Bottom line

Built the same way on the same hardware, wolfNano (wolfCrypt's asm via the slim
seam) is **12–14x** faster on AES-GCM and **24–72x** on the public-key
operations that gate TLS and secure boot, and it ships a complete post-quantum
suite MbedTLS does not have — all from a TLS-1.3-only, zero-configure,
no-allocator build. ARM and Cortex-M numbers follow on device (HANDOFF).
