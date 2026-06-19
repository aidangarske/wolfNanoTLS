<div align="center">

<img src="docs/images/wolfnano-logo.png" width="280" alt="wolfNano logo" />

**A condensed, TLS 1.3-only, zero-allocation embedded TLS library, built as a
thin shell on top of [wolfSSL](https://www.wolfssl.com/).**

[![CI](https://img.shields.io/github/actions/workflow/status/aidangarske/wolfNano/build-test.yml?label=CI&logo=github)](https://github.com/aidangarske/wolfNano/actions)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSING)
[![TLS](https://img.shields.io/badge/TLS-1.3%20only-blueviolet)](https://www.rfc-editor.org/rfc/rfc8446)

</div>

---

wolfNano is a **behavioral subset of wolfSSL**: the components you want for the
smallest constrained MCUs, assembled into a plain-Makefile project (in the
spirit of wolfCOSE / wolfIP). It consumes wolfSSL as a **pinned git submodule
and never modifies it**, reaching crypto only through a thin `wc_*` provider
seam. It never offers a primitive, group, suite, or extension wolfSSL lacks, so
interop stays identical to wolfSSL.

## Main Features

- **TLS 1.3 only**: client-first, Raw Public Keys (RFC 7250) + PSK by default;
  X.509 is a compile-time adder. No TLS 1.2, no compatibility layer.
- **Zero dynamic allocation**: the product shell and `src` crypto floor run
  entirely on caller-provided / static buffers (`WOLFSSL_NO_MALLOC`), verified
  with a malloc trap. Nothing on the heap.
- **Tiny footprint**: a complete Cortex-M33 TLS 1.3 client is **31.0 KB**
  (PSK + ECDHE, no X.509) or **76.9 KB** (cert / X.509) of `.text`, both
  measured against the same minimal MbedTLS config (**2.60x** and **1.59x**
  smaller). The slim shell itself is ~8.7 KB vs wolfSSL's TLS layer at ~52 KB.
- **Full wolfSSL asm speed**: target assembly is linked unchanged from the
  submodule. On x86_64, AES-128-GCM hits **2.7 GB/s** and ECDSA P-256 verify
  **~72x** MbedTLS, with none of wolfSSL's configure surface.
- **Post-quantum ready**: ML-KEM-768 (+ X25519MLKEM768 hybrid) and ML-DSA are
  compile-out-able adders.
- **Per-algorithm compile flags** (`WOLFNANO_HAVE_*`): every algorithm and
  feature is behind one switch; off means no undefined references.
- **Path to FIPS**: a `WOLFNANO_CRYPTO=fips` build links a customer-supplied
  validated wolfCrypt bundle under the byte-identical shell (TLS layer is
  outside the boundary).

## Supported Algorithms

**Key exchange:** `ECDHE P-256/P-384, X25519, ML-KEM-768, X25519MLKEM768 (hybrid)`

**Signatures:** `ECDSA P-256/P-384, Ed25519, RSA-PSS (verify), ML-DSA (verify)`

**AEAD:** `AES-128/256-GCM, ChaCha20-Poly1305`

**Hash / KDF:** `SHA-256, SHA-384, SHA3-256, HMAC, HKDF`

The offered cipher-suite and group lists are a function of the active backend,
so a `fips` build never advertises a primitive outside its boundary.

## Footprint (Cortex-M33, measured)

Complete TLS 1.3 client linked from source for Cortex-M33
(`arm-none-eabi-gcc -Os --gc-sections`), every library at the **same minimal
scope**. `.text` bytes:

| Build | wolfNano | MbedTLS | wolfSSL | vs MbedTLS |
|---|--:|--:|--:|--:|
| PSK + ECDHE (no X.509) | **31.0 KB** | 80.7 KB | (n/a) | **2.60x smaller** |
| cert / X.509 | **76.9 KB** | 122.1 KB | 162.0 KB | **1.59x smaller** |

Reproduce with `sh bench/footprint-min.sh`. See
[Footprint](https://github.com/aidangarske/wolfNano/wiki/Footprint).

## Speed (x86_64, vs MbedTLS, same host)

wolfNano's `intel` build (wolfCrypt asm through the seam) vs MbedTLS 3.6.0 fast
config, both `-O2 -march=native`:

| Operation | wolfNano | MbedTLS | faster |
|---|--:|--:|--:|
| AES-128-GCM | 1682 MiB/s | 119 MiB/s | ~14x |
| ECDSA P-256 verify | 9386 op/s | 130 op/s | ~72x |
| ECDSA P-256 sign | 20799 op/s | 721 op/s | ~29x |
| ECDH P-256 agree | 9472 op/s | 390 op/s | ~24x |

Plus a full PQC + EdDSA suite MbedTLS does not have. See
[Benchmarks](https://github.com/aidangarske/wolfNano/wiki/Benchmarks).

## Status

Early development, but functional. The wolfNano TLS 1.3 client completes a
**live PSK + ECDHE handshake against both OpenSSL and wolfSSL**; the crypto
floor is validated by RFC-vector KATs and wolfSSL's own crypto test, true
no-allocation is verified, and side-channel hardening is on. PQC, X.509, and the
FIPS backend are wired and proven; the handshake state machine continues to
fill in.

## Build

```sh
git clone --recursive https://github.com/aidangarske/wolfNano.git
cd wolfNano
make test        # build + run all suites
make interop     # live TLS 1.3 handshake vs OpenSSL / wolfSSL
make bench       # all-algo speed table (portable C vs Intel asm)
```

| Target | Description |
|---|---|
| `make test` | Build and run all unit / KAT suites |
| `make interop` | Live handshake vs OpenSSL, wolfSSL, MbedTLS |
| `make bench` | All-algo benchmark, `WOLFNANO_ASM=none` vs `=intel` |
| `make targets` | Cross-compile the floor for every `WOLFNANO_ASM` arch |
| `make fipsproof` | Build the shell against a wolfCrypt FIPS bundle |
| `make clean` | Remove build artifacts |

Pick the accelerated backend with `WOLFNANO_ASM=intel|thumb2|aarch64|armv7|riscv64`
(default `none` is portable C). See
[Macros](https://github.com/aidangarske/wolfNano/wiki/Macros).

## CI / Testing

Runs on every push and PR:

- **Build + Test**: Ubuntu + macOS, GCC + Clang, against the pinned, latest
  stable, and master wolfSSL submodule
- **Standards**: house style, no bare-scope braces, C89 `-Werror`, the
  zero-allocation grep
- **Static analysis**: CodeQL, Semgrep, cppcheck, codespell
- **Sanitizers**: ASAN / UBSAN
- **Nightly**: coverage, stack bounds, Coverity, footprint + speed vs MbedTLS,
  and a green-gated auto-bump of the wolfSSL pin to a known-good master

See [CI](https://github.com/aidangarske/wolfNano/wiki/CI).

## Documentation

Full documentation lives in the
[Wiki](https://github.com/aidangarske/wolfNano/wiki):

- [Getting Started](https://github.com/aidangarske/wolfNano/wiki/Getting-Started)
- [Architecture](https://github.com/aidangarske/wolfNano/wiki/Architecture)
- [Algorithms](https://github.com/aidangarske/wolfNano/wiki/Algorithms)
- [Macros](https://github.com/aidangarske/wolfNano/wiki/Macros)
- [Footprint](https://github.com/aidangarske/wolfNano/wiki/Footprint)
- [Benchmarks](https://github.com/aidangarske/wolfNano/wiki/Benchmarks)
- [FIPS](https://github.com/aidangarske/wolfNano/wiki/FIPS)
- [Testing](https://github.com/aidangarske/wolfNano/wiki/Testing)
- [CI](https://github.com/aidangarske/wolfNano/wiki/CI)
- [Positioning](https://github.com/aidangarske/wolfNano/wiki/Positioning)

## License

wolfNano is free software licensed under
[GPLv3](https://www.gnu.org/licenses/gpl-3.0.html); see [LICENSING](LICENSING)
and [COPYING](COPYING). The `fips` build path is not GPLv3-only.

Copyright (C) 2006-2026 wolfSSL Inc.

## Support

For commercial licensing or support, contact
[wolfSSL](https://www.wolfssl.com/contact/).
