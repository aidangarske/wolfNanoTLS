<div align="center">

<img src="docs/images/wolfnano-logo.png" width="290" alt="wolfNanoTLS logo" />

**A condensed, TLS 1.3-only, zero-allocation embedded TLS library, built as a
thin shell on top of [wolfSSL](https://github.com/wolfSSL/wolfssl).**

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)](https://github.com/aidangarske/wolfNanoTLS/actions)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSING)
[![TLS](https://img.shields.io/badge/TLS-1.3%20only-blueviolet)](https://www.rfc-editor.org/rfc/rfc8446)

</div>

---

wolfNanoTLS is a **behavioral subset of wolfSSL**: the components you want for the
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
- **Tiny footprint**: a complete Cortex-M33 TLS 1.3 PSK + ECDHE client is
  **17.6 KB** of `.text` (X25519) or **25.2 KB** (P-256); the cert / X.509
  client is **60.8 KB**, and the slim shell itself is **~8.7 KB**. That is far
  smaller than any embedded TLS stack of comparable standing; see
  [Footprint](https://github.com/aidangarske/wolfNanoTLS/wiki/Footprint).
- **Full wolfSSL asm speed**: target assembly is linked unchanged from the
  submodule. On x86_64, AES-128-GCM hits **2.7 GB/s** and ECDSA P-256 sign
  **26K ops/s** - the full wolfCrypt asm speed with none of wolfSSL's configure
  surface; see [Benchmarks](https://github.com/aidangarske/wolfNanoTLS/wiki/Benchmarks).
- **Post-quantum ready**: ML-KEM-768 (+ X25519MLKEM768 hybrid) and ML-DSA are
  compile-out-able adders.
- **Per-algorithm compile flags** (`WOLFNANOTLS_HAVE_*`): every algorithm and
  feature is behind one switch; off means no undefined references.
- **FIPS 140-3**: a `WOLFNANOTLS_CRYPTO=fips` build runs all TLS 1.3 crypto through
  the **validated wolfCrypt module** (verified against v5.2.4, Cert #4718:
  in-core integrity self-test + CASTs pass through the seam). The TLS shell is
  outside the boundary, so only the validated module does cryptography; see
  [FIPS](https://github.com/aidangarske/wolfNanoTLS/wiki/FIPS).

## Supported Algorithms

**Key exchange:** `ECDHE P-256/P-384, X25519, ML-KEM-768, X25519MLKEM768 (hybrid)`

**Signatures:** `ECDSA P-256/P-384, Ed25519, RSA-PSS (verify), ML-DSA (verify)`

**AEAD:** `AES-128/256-GCM, ChaCha20-Poly1305`

**Hash / KDF:** `SHA-256, SHA-384, SHA3-256, HMAC, HKDF`

The offered cipher-suite and group lists are a function of the active backend,
so a `fips` build never advertises a primitive outside its boundary.

## Footprint (Cortex-M33, measured)

Whole TLS 1.3 client linked from source for Cortex-M33 (AES-128-GCM, SHA-256),
`arm-none-eabi-gcc -Os -flto --gc-sections` + nano specs (ArmGNU 14.2). `.text`:

| Client | wolfNanoTLS `.text` |
|---|--:|
| PSK + ECDHE, X25519 | **17.6 KB** |
| PSK + ECDHE, P-256 | **25.2 KB** |
| cert / X.509, P-256 | **60.8 KB** |

At ~17 KB the PSK client fits Cortex-M0+/M3/M4 parts from ~32 KB flash, well
below where embedded TLS stacks of comparable standing land. The default curve
is **X25519** (smallest); set `WOLFNANOTLS_HAVE_ECDHE_P256` (or `WOLFNANOTLS_FIPS`) to
negotiate **P-256** for FIPS / broad interop. Both are interop-verified against
OpenSSL and wolfSSL.

A like-for-like, hard-minimized comparison against mbedTLS (wolfNanoTLS is 49-57%
smaller), the reproduction steps, and the exact build configs live in
[Footprint](https://github.com/aidangarske/wolfNanoTLS/wiki/Footprint).

## Speed (x86_64, measured)

wolfNanoTLS's `intel` build runs wolfCrypt assembly through the `wc_*` seam
(`-O2 -march=native`), reaching full wolfSSL asm speed:

| Operation | wolfNanoTLS |
|---|--:|
| AES-128-GCM | 2.7 GB/s |
| ECDSA P-256 sign | 26446 op/s |
| ECDSA P-256 verify | 10013 op/s |
| ECDH P-256 agree | 10546 op/s |

Plus a full PQC + EdDSA suite. The portable-C baseline, the per-algorithm
speedups, and a head-to-head vs mbedTLS are in
[Benchmarks](https://github.com/aidangarske/wolfNanoTLS/wiki/Benchmarks).

## Status

Early development, but functional end-to-end. The wolfNanoTLS client completes a
**live TLS 1.3 PSK + ECDHE handshake against OpenSSL, wolfSSL, and mbedTLS**,
then exchanges application data and closes cleanly via `wn_Send` / `wn_Recv` /
`wn_Close` (post-handshake NewSessionTicket and KeyUpdate are handled
transparently). The crypto floor is validated by RFC-vector KATs and wolfSSL's
own crypto test, true no-allocation is verified, and side-channel hardening is
on. PQC, X.509, and the FIPS 140-3 backend are wired and proven.

## Usage

```c
wn_Session sess;
byte scratch[8192], buf[512];
word32 got;

/* PSK + ECDHE handshake, keeping a session for application data */
wn_Connect_Psk_ex(&sess, &rng, mySend, myRecv, &fd, psk, pskLen,
                  "Client_identity", scratch, sizeof(scratch));
wn_Send(&sess, (const byte*)"hello", 5);
wn_Recv(&sess, buf, sizeof(buf), &got);
wn_Close(&sess);
```

`mySend` / `myRecv` are your transport callbacks (`wn_IoSend` / `wn_IoRecv`).
See [examples/client.c](examples/client.c) for a complete runnable client and
`make example`.

## Build

```sh
git clone --recursive https://github.com/aidangarske/wolfNanoTLS.git
cd wolfNanoTLS
make test        # build + run all suites
make interop     # live TLS 1.3 handshake vs OpenSSL / wolfSSL
make bench       # all-algo speed table (portable C vs Intel asm)
```

| Target | Description |
|---|---|
| `make test` | Build and run all unit / KAT suites |
| `make interop` | Live handshake vs OpenSSL, wolfSSL, mbedTLS |
| `make bench` | All-algo benchmark, `WOLFNANOTLS_ASM=none` vs `=intel` |
| `make targets` | Cross-compile the floor for every `WOLFNANOTLS_ASM` arch |
| `make fipsproof` | Build the shell against a wolfCrypt FIPS bundle |
| `make clean` | Remove build artifacts |

Pick the accelerated backend with `WOLFNANOTLS_ASM=intel|thumb2|aarch64|armv7|riscv64`
(default `none` is portable C). See
[Macros](https://github.com/aidangarske/wolfNanoTLS/wiki/Macros).

## CI / Testing

Runs on every push and PR:

- **Build + Test**: Ubuntu x86_64 + arm64, GCC + Clang, against the pinned,
  latest stable, and master wolfSSL submodule
- **Coverage gate**: **100% line coverage of every `src/` file**, enforced
  (`.github/ci/coverage-100.txt`); reachable code only, justified `LCOV_EXCL` otherwise
- **Stack gate**: per-function stack budget (<= 5 KB), enforced
- **Standards**: house style, no bare-scope braces, C89 `-Werror`, the
  zero-allocation grep
- **Static analysis**: Semgrep, cppcheck, codespell
- **Sanitizers**: ASAN / UBSAN (incl. the full handshake via the mock-server test)
- **Fuzzing**: libFuzzer over the ServerHello, record, and wire-reader parsers
- **Nightly**: Coverity, footprint + speed vs mbedTLS, and a green-gated
  auto-bump of the wolfSSL pin to a known-good master

See [CI](https://github.com/aidangarske/wolfNanoTLS/wiki/CI).

## Documentation

Full documentation lives in the
[Wiki](https://github.com/aidangarske/wolfNanoTLS/wiki):

- [Getting Started](https://github.com/aidangarske/wolfNanoTLS/wiki/Getting-Started)
- [Architecture](https://github.com/aidangarske/wolfNanoTLS/wiki/Architecture)
- [Algorithms](https://github.com/aidangarske/wolfNanoTLS/wiki/Algorithms)
- [Macros](https://github.com/aidangarske/wolfNanoTLS/wiki/Macros)
- [Footprint](https://github.com/aidangarske/wolfNanoTLS/wiki/Footprint)
- [Benchmarks](https://github.com/aidangarske/wolfNanoTLS/wiki/Benchmarks)
- [FIPS](https://github.com/aidangarske/wolfNanoTLS/wiki/FIPS)
- [Testing](https://github.com/aidangarske/wolfNanoTLS/wiki/Testing)
- [CI](https://github.com/aidangarske/wolfNanoTLS/wiki/CI)
- [Positioning](https://github.com/aidangarske/wolfNanoTLS/wiki/Positioning)

## License

wolfNanoTLS is free software licensed under
[GPLv3](https://www.gnu.org/licenses/gpl-3.0.html); see [LICENSING](LICENSING)
and [COPYING](COPYING). The `fips` build path is not GPLv3-only.

Copyright (C) 2006-2026 wolfSSL Inc.

## Support

For commercial licensing or support, contact
[wolfSSL](https://www.wolfssl.com/contact/).
