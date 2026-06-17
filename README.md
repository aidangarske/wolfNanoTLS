# wolfNanoTLS

A condensed, **TLS 1.3-only** embedded TLS library: the wolfSSL components you
want for the smallest constrained MCUs, assembled into a plain-Makefile project
(in the spirit of wolfCOSE / wolfIP) with **zero dynamic allocation** and
wolfSSL's target-specific assembly speedups intact.

wolfNanoTLS is a **behavioral subset of wolfSSL**: it never offers a primitive,
group, suite, or extension wolfSSL lacks. It consumes wolfSSL as a pinned git
submodule and **never modifies it**; crypto is reached through a thin `wc_*`
provider seam.

## Design at a glance

- **TLS 1.3 only**, client-first, Raw Public Keys (RFC 7250) + PSK by default;
  X.509 is a compile-time adder.
- **True no-allocator** product shell + `src` crypto floor (caller/static
  buffers, `WOLFSSL_NO_MALLOC`).
- **Provider seam** (`WOLFNANOTLS_CRYPTO`):
  - `src` (default, GPLv3): selected `wolfcrypt/src/*.c` from the submodule.
  - `fips` (commercial): links a customer-supplied wolfSSL FIPS bundle under
    the unchanged shell.
- **Per-algorithm compile flags** (`WOLFNANOTLS_HAVE_*`); ML-KEM / ML-DSA are
  compile-out-able adders.
- **Assembly** kept verbatim from the submodule (Thumb2 + SP Cortex-M on the
  STM32H563 / Cortex-M33 reference target).

## Status

Early development, but functional: the wolfNanoTLS TLS 1.3 client completes a
**live PSK+ECDHE handshake against OpenSSL**, with the crypto floor validated by
both RFC-vector KATs and wolfSSL's own (config-trimmed) crypto test, true
no-allocation verified, and side-channel hardening on. The full TLS 1.3 client
shell is ~1.3k lines / ~8.7 KB `.text` (vs wolfSSL's `tls13.c`+`tls.c` alone at
~52 KB). Run `make test` for the suites and `make interop` for the live
handshake. Next: Raw-Public-Key auth, PQC, X.509, the FIPS backend.

## License

GPLv3 (see `COPYING` / `LICENSING`) or wolfSSL commercial. Copyright (C)
2006-2026 wolfSSL Inc. The `fips` build path is not GPLv3-only.
