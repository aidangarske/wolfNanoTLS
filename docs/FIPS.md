# FIPS

wolfNano keeps FIPS reachable without forking, through the provider seam. It does
this differently from a fork like wolfTLS, but with the same honesty.

## How it works

The validated wolfSSL FIPS module is a separate, commercially-licensed
distribution with its own version lineage. It contains `fips.c`, the in-core
integrity check, and the boundary file set. None of that lives in the public
wolfSSL tree, so wolfNano cannot produce a validatable module by pinning the
github submodule.

Instead, the shell calls crypto only through the `wc_*` seam, and the backend is
chosen at build time:

- `WOLFNANO_CRYPTO=src`: the public submodule crypto, GPLv3. This is the default.
- `WOLFNANO_CRYPTO=fips`: links a customer-supplied, licensed wolfSSL FIPS bundle
  under the unchanged shell. This build path is commercial, not GPLv3-only.

The goal is that the exact same shell objects link against both backends with
zero shell source changes.

## Honest caveats

- The FIPS module is a licensed artifact the user supplies; wolfNano does not
  ship or reproduce it.
- The offered cipher suites and groups are derived from the active backend, so a
  `fips` build never advertises a primitive outside its boundary (for example
  ChaCha20-Poly1305 or X25519).
- PQC under FIPS is pending, not validated.
- Linking the bundle and passing the integrity check is necessary but not
  sufficient: validation on a given board also depends on that operational
  environment being covered by the active certificate.

The `fips` backend may allocate internally; its memory model is frozen at
validation. The true-no-allocator guarantee is asserted for the `src` build.
