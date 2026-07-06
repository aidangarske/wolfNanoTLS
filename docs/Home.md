# wolfNanoTLS

A condensed, TLS 1.3-only embedded TLS library: the wolfSSL components you want
for the smallest constrained devices, assembled into a plain-Makefile project
(in the spirit of wolfCOSE and wolfIP), with true zero dynamic allocation and
wolfSSL's assembly speedups intact.

wolfNanoTLS is a behavioral subset of wolfSSL. It never offers a primitive, group,
cipher suite, or extension that wolfSSL lacks, it consumes wolfSSL as a pinned
git submodule, and it never modifies that submodule. The shell reaches crypto
only through a thin `wc_*` provider seam.

## Pillars

- **TLS 1.3 only**, client-first, external PSK + ECDHE by
  default. X.509 server-cert auth is a compile-time adder.
- **True no-allocator**: the shell and the `src` crypto floor use no allocator
  at all, only caller-provided or static buffers (the wolfCOSE bar).
- **Provider seam** selected at build time:
  - `src` (default, GPLv3): selected `wolfcrypt/src/*.c` from the submodule.
- **Per-feature compile flags** (`WOLFNANO_HAVE_*`). ML-KEM and ML-DSA are
  compile-out-able adders.
- **Clean-room provenance**: copy wolfSSL-family code verbatim, write everything
  else strictly from the RFC, never from third-party sources.

## Current status

Early development, but the TLS 1.3 client works end to end.

- Done: the crypto floor (RFC KATs + wolfSSL's own crypto test, trimmed) with
  true no-allocator verified; the slim TLS 1.3 shell (key schedule, transcript,
  record protection, key share, ClientHello/ServerHello, handshake driver);
  side-channel hardening; and a **live TLS 1.3 PSK+ECDHE handshake against both
  OpenSSL and wolfSSL**.
- Done (PQC): ML-KEM-768 and ML-DSA-65 adders (both verify paths
  allocation-free) plus the X25519MLKEM768 hybrid key share.
- Done (cert auth): X.509 chain-link verify (ECC + RSA) and a **cert-based
  TLS 1.3 handshake (ECDSA CertVerify) live against OpenSSL** (`WOLFNANO_X509`,
  needs working memory).
- Next: benchmarks/positioning.
- Deferred: full multi-cert path validation, hardware/on-device asm benchmarks.

See [Getting Started](Getting-Started.md).
