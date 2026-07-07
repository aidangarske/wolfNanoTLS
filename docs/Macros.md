# Macros

Configuration lives in `user_settings.h`. Crypto capabilities are selected with
wolfSSL's own macros; `wolfnano_config.h` fills in prerequisites and applies the
standing size cuts, and `wolfnano_target.h` selects the asm/SP bundle.
wolfNano-owned `WOLFNANO_*` macros are reserved for policy that wolfSSL has no
macro for: the TLS group offer, X.509 sub-options, PQC level, and memory model.

## Crypto capabilities (wolfSSL macros)

Set these directly in `user_settings.h`; `wolfnano_config.h` completes the
prerequisites and cuts. SHA-256 is on by default.

| wolfSSL macro | Enables |
|---|---|
| `WOLFSSL_SHA384` | SHA-384 (pulls SHA-512) |
| `HAVE_HKDF` | HKDF (TLS 1.3 key schedule) |
| `HAVE_AESGCM` | AES-GCM |
| `HAVE_CHACHA` | ChaCha20-Poly1305 (pulls `HAVE_POLY1305`) |
| `HAVE_ECC` | ECDHE + ECDSA P-256 (pulls `ECC_USER_CURVES`) |
| `HAVE_ECC384` | adds P-384 |
| `HAVE_CURVE25519` | X25519 |
| `HAVE_ED25519` | Ed25519 (pulls SHA-512) |

## wolfNanoTLS policy macros (`WOLFNANO_*`)

Owned by wolfNanoTLS; no wolfSSL equivalent.

| Flag | Enables | Effect |
|---|---|---|
| `WOLFNANO_HAVE_ECDHE_P256` | offer secp256r1 as the (EC)DHE group | single-group-per-build selector |
| `WOLFNANO_HAVE_MLKEM_HYBRID` | offer X25519MLKEM768 as the group | pulls ML-KEM-768 + X25519 |
| `WOLFNANO_HAVE_RSA_VERIFY` | RSA verify (cert chains, RSA-PSS) | `WOLFSSL_RSA_VERIFY_ONLY`, `WC_RSA_PSS`, 4096 ceiling |
| `WOLFNANO_RSA_FULL` | adds RSA keygen/sign (tooling, not the no-alloc product) | `WOLFSSL_KEY_GEN` |
| `WOLFNANO_X509` | X.509 cert path; parses/verifies with wolfSSL's full `asn.c`/`DecodedCert` by default (complete, proven) | cert path + `WOLFSSL_SMALL_CERT_VERIFY` |
| `WOLFNANO_X509_LITE` | opt into the smaller native `wn_x509` parser instead of `asn.c` (~15% / ~10 KB less `.text`). A stricter-but-narrower size tier: no name constraints/policies/CRL/OCSP, capped SAN pool; the handshake enforces the same `wn_VerifyChain` checks on both backends. Default off = asn.c. `make ... X509_LITE=1` | swaps the cert parse + CertificateVerify key-import backend |
| `WOLFNANO_X509_HOSTNAME` | leaf hostname (SAN/CN, RFC 6125) matching; default on with `WOLFNANO_X509`. Set `0` for a key-pin-only cert build (~0.5 KB smaller) | gates `wn_CheckServerName` |
| `WOLFNANO_NO_X509_TIME` | opt out of leaf/intermediate validity (notBefore/notAfter) checking; for clockless devices only. Default: cert builds enforce dates via the `XTIME` clock seam | drops `wn_CertTimeValid` |
| `WOLFNANO_MLKEM` | ML-KEM-768 + X25519MLKEM768 hybrid | `WOLFSSL_HAVE_MLKEM` |
| `WOLFNANO_MLDSA` | ML-DSA verify (no-malloc) | `WOLFSSL_HAVE_MLDSA`, verify-only |
| `WOLFNANO_MLDSA_LEVEL` | ML-DSA security level 2/3/5 (default 2) | selects ML-DSA-44/65/87 |
| `WOLFNANO_MLDSA_SIGN` | adds ML-DSA keygen/sign (needs memory) | drops verify-only |
| `WOLFNANO_SERVER` | TLS 1.3 server (`wn_Accept_Psk` / `wn_Accept_Cert`), off by default; reuses the sub-adders above for groups and cert-sign algorithms | server shell + ClientHello decoder + ServerHello/Certificate encoders |
| `WOLFNANO_SEND_ALERTS` | emit a fatal TLS alert on handshake failure (off by default) | RFC 8446 6.2 alert codes |

When a feature is off, the build has no undefined references for it.

## Handshake curve selection (offer both, pick one per build)

The (EC)DHE key-exchange curve is chosen at build time; the key share is
single-curve per build to keep the footprint minimal.

| Build flags | Negotiated group | PSK client `.text` | Use when |
|---|---|---|---|
| *(default)* | X25519 (0x001d) | **17.2 KB** | smallest build; X25519 is cryptographically strong (Curve25519) |
| `WOLFNANO_HAVE_ECDHE_P256` | secp256r1 (0x0017) | **24.8 KB** | CNSA, or maximum enterprise interop |

Both are interop-verified live against OpenSSL and wolfSSL. X25519 is **not**
weaker than P-256 - it was simply standardized later (NIST SP 800-186, 2023).
Default to X25519 for size; select P-256 when broad interop requires it.

## Asm / speedup selection (`WOLFNANO_ASM=<arch>`)

One Makefile switch bundles a target's asm macros (`wolfnano_target.h`) + asm
source files + toolchain/`-march`, mirroring wolfSSL `--enable-intelasm` /
`--enable-armasm` / `--enable-sp=yes,asm` but with no `./configure`. Default is
the lightweight generic-math build; the fast specialized SP + symmetric asm is
opt-in (larger code, the speed/size trade is the customer's, as in wolfSSL).

| `WOLFNANO_ASM` | target | speedups | status |
|---|---|---|---|
| `none` (default) | PORTABLE_C | none (generic `WOLFSSL_SP_MATH_ALL`) | run + tested |
| `intel` | x86_64 | AES-NI, AVX1/2, SP x86_64 asm, AVX2 ML-KEM/ML-DSA | run + tested |
| `thumb2` | Cortex-M33 | Thumb2 AES/SHA asm + SP Cortex-M asm | cross-builds |
| `aarch64` | ARMv8-A | NEON + crypto-ext AES/SHA + SP arm64 asm | scaffolded |
| `armv7` | ARMv8-32 | 32-bit ARM asm + SP arm32 asm | cross-builds |
| `riscv64` | RISC-V 64 | scalar AES/SHA/ChaCha asm (SP stays C) | scaffolded |

`make bench` runs the all-algo benchmark for `none` then `intel`. `make targets`
cross-compiles the floor for every non-host arch (skips cleanly without a
toolchain). See [Benchmarks](Benchmarks.md).

## Backend selection

- `WOLFNANO_CRYPTO=src` (default): submodule crypto, GPLv3.

## Build toggles

- Memory model: default is plain wolfSSL (heap). Set wolfSSL's own macro to
  change it - `WOLFSSL_SMALL_STACK` (embedded) or `WOLFSSL_NO_MALLOC` (zero
  dynamic allocation). The `MEM` build convenience emits the `-D`:
  `MEM=smallstack` / `MEM=nomalloc`. (`WOLFSSL_STATIC_MEMORY` pool support is a
  planned follow-up - it needs a heap hint threaded through the shell, so it is
  not yet a selectable model.)
- `WOLFNANO_ASM=<arch>`: select the asm/speedup bundle (see above); default
  `none`. The target macro it sets (`WOLFNANO_TARGET_*`) drives
  `wolfnano_target.h`.

## Standing size cuts

Always applied in `wolfnano_config.h`: no old TLS, no MD5/SHA-1/DES3/RC4/DSA,
no RSA/DH, no PWDBASED/PKCS12, single-threaded, no filesystem, no error
strings. Cert-time validation (`NO_ASN_TIME`) is off in PSK-only builds; the
X.509 adder turns ASN time on and enforces leaf/intermediate validity via the
`XTIME` clock seam (opt out with `WOLFNANO_NO_X509_TIME`).
