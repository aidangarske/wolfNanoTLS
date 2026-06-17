# wolfNano

A condensed, TLS 1.3-only embedded TLS library: the wolfSSL components you want
for the smallest constrained devices, assembled into a plain-Makefile project
(in the spirit of wolfCOSE and wolfIP), with true zero dynamic allocation and
wolfSSL's assembly speedups intact.

wolfNano is a behavioral subset of wolfSSL. It never offers a primitive, group,
cipher suite, or extension that wolfSSL lacks, it consumes wolfSSL as a pinned
git submodule, and it never modifies that submodule. The shell reaches crypto
only through a thin `wc_*` provider seam.

## Pillars

- **TLS 1.3 only**, client-first, Raw Public Keys (RFC 7250) plus PSK by
  default. X.509 is a compile-time adder.
- **True no-allocator**: the shell and the `src` crypto floor use no allocator
  at all, only caller-provided or static buffers (the wolfCOSE bar).
- **Provider seam** selected at build time:
  - `src` (default, GPLv3): selected `wolfcrypt/src/*.c` from the submodule.
  - `fips` (commercial): links a customer-supplied wolfSSL FIPS bundle under the
    unchanged shell.
- **Per-feature compile flags** (`WOLFNANO_HAVE_*`). ML-KEM and ML-DSA are
  compile-out-able adders.
- **Clean-room provenance**: copy wolfSSL-family code verbatim, write everything
  else strictly from the RFC, never from third-party sources.

## Current status

Early development.

- Done: the crypto floor builds and passes its KATs locally (mac/linux), with
  true no-allocator verified and a pluggable entropy seed hook.
- Next: the slim hand-written TLS 1.3 shell.
- Deferred: hardware targets and assembly, PQC adders, X.509, the FIPS backend.

See [Getting Started](Getting-Started.md).
