# Macros

Configuration lives in `user_settings.h`, which selects `WOLFNANOTLS_HAVE_*`
features and includes `wolfnano_target.h` (asm/SP bundle) and
`wolfnano_config.h` (which maps the selections to real wolfSSL macros and
applies the standing size cuts).

## Feature selection (`WOLFNANOTLS_HAVE_*`)

| Flag | Enables | wolfSSL macro(s) |
|---|---|---|
| `WOLFNANOTLS_HAVE_SHA256` | SHA-256 (default on) | default; `NO_SHA256` drops it |
| `WOLFNANOTLS_HAVE_SHA384` | SHA-384/512 | `WOLFSSL_SHA384`, `WOLFSSL_SHA512` |
| `WOLFNANOTLS_HAVE_HKDF` | HKDF (TLS 1.3 key schedule) | `HAVE_HKDF` |
| `WOLFNANOTLS_HAVE_AESGCM` | AES-GCM | `HAVE_AESGCM` |
| `WOLFNANOTLS_HAVE_CHACHA` | ChaCha20-Poly1305 | `HAVE_CHACHA`, `HAVE_POLY1305` |
| `WOLFNANOTLS_HAVE_ECC` | ECDHE + ECDSA (P-256) | `HAVE_ECC`, `ECC_USER_CURVES` |
| `WOLFNANOTLS_HAVE_ECC384` | adds P-384 | `HAVE_ECC384` |
| `WOLFNANOTLS_HAVE_CURVE25519` | X25519 | `HAVE_CURVE25519` |
| `WOLFNANOTLS_HAVE_ED25519` | Ed25519 | `HAVE_ED25519` (pulls SHA-512) |
| `WOLFNANOTLS_HAVE_RSA_VERIFY` | RSA verify (cert chains, RSA-PSS) | `WOLFSSL_RSA_VERIFY_ONLY`, `WC_RSA_PSS` |
| `WOLFNANOTLS_RSA_FULL` | adds RSA keygen/sign (tooling, not the no-alloc product) | `WOLFSSL_KEY_GEN` |
| `WOLFNANOTLS_X509` | X.509 cert path (needs heap) | cert path + `WOLFSSL_SMALL_CERT_VERIFY` |
| `WOLFNANOTLS_MLKEM` | ML-KEM-768 + X25519MLKEM768 hybrid | `WOLFSSL_HAVE_MLKEM` |
| `WOLFNANOTLS_MLDSA` | ML-DSA-65 verify (no-malloc) | `WOLFSSL_HAVE_MLDSA`, verify-only |
| `WOLFNANOTLS_MLDSA_SIGN` | adds ML-DSA keygen/sign (needs memory) | drops verify-only |
| `WOLFNANOTLS_FIPS` | approved-mode suites (ECDHE P-256 + AES-GCM only) | drops X25519/ChaCha/Ed25519 from offers |

When a feature is off, the build has no undefined references for it.

## Asm / speedup selection (`WOLFNANOTLS_ASM=<arch>`)

One Makefile switch bundles a target's asm macros (`wolfnano_target.h`) + asm
source files + toolchain/`-march`, mirroring wolfSSL `--enable-intelasm` /
`--enable-armasm` / `--enable-sp=yes,asm` but with no `./configure`. Default is
the lightweight generic-math build; the fast specialized SP + symmetric asm is
opt-in (larger code, the speed/size trade is the customer's, as in wolfSSL).

| `WOLFNANOTLS_ASM` | target | speedups | status |
|---|---|---|---|
| `none` (default) | PORTABLE_C | none (generic `WOLFSSL_SP_MATH_ALL`) | run + tested |
| `intel` | x86_64 | AES-NI, AVX1/2, SP x86_64 asm, AVX2 ML-KEM/ML-DSA | run + tested |
| `thumb2` | Cortex-M33 | Thumb2 AES/SHA asm + SP Cortex-M asm | cross-builds |
| `aarch64` | ARMv8-A | NEON + crypto-ext AES/SHA + SP arm64 asm | scaffolded |
| `armv7` | ARMv8-32 | 32-bit ARM asm + SP arm32 asm | cross-builds |
| `riscv64` | RISC-V 64 | scalar AES/SHA/ChaCha asm (SP stays C) | scaffolded |

`make bench` runs the all-algo benchmark for `none` then `intel`. `make targets`
cross-compiles the floor for every non-host arch (skips cleanly without a
toolchain). See [Benchmarks](Benchmarks.md) and [HANDOFF](HANDOFF.md).

## Backend selection

- `WOLFNANOTLS_CRYPTO=src` (default): submodule crypto, GPLv3.
- `WOLFNANOTLS_CRYPTO=fips`: customer-supplied FIPS bundle (see [FIPS](FIPS.md)).

## Build toggles

- `MALLOC=1`: relax the true-no-allocator bar during bring-up
  (`-DWOLFNANOTLS_ALLOW_MALLOC`).
- `WOLFNANOTLS_ASM=<arch>`: select the asm/speedup bundle (see above); default
  `none`. The target macro it sets (`WOLFNANOTLS_TARGET_*`) drives
  `wolfnano_target.h`.

## Standing size cuts

Always applied in `wolfnano_config.h`: no old TLS, no MD5/SHA-1/DES3/RC4/DSA,
no RSA/DH, no PWDBASED/PKCS12, single-threaded, no filesystem, no error
strings. Cert-time validation (`NO_ASN_TIME`) stays off until the X.509 adder,
which brings a time hook.
