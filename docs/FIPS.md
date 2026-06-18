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

## Proving the seam (`make fipsproof`)

`make fipsproof` builds the seam against a wolfSSL FIPS bundle and runs two
checks. Point `WOLFNANO_FIPS_DIR` at a built bundle (a FIPS Ready download works
for the seam proof; a licensed validated module is needed for an actual
certificate). The target was developed against wolfCrypt v7.0.0 FIPS.

1. The handshake's FIPS-boundary crypto (SHA-256, HMAC, TLS 1.3 HKDF
   Extract/Expand-Label, AES-GCM) runs through the unchanged `wc_*` seam header
   and the in-core integrity / power-on self-test status reads clean.
2. The same shell source compiled against the `src` and `fips` headers yields the
   same logical `wc_*` seam surface; the `fips` build only routes each call to
   its `_fips` boundary wrapper. No shell source changes.

Two integration points the seam proof surfaced, both handled the way wolfSSL's
own `tls13.c` handles them under `HAVE_FIPS`:

- **Per-binary in-core hash.** The in-core integrity hash is specific to the
  final linked artifact, so each consumer derives it once for its own binary
  (patch `fips_test.c`, rebuild the module, relink). The proof harness automates
  this. The whole archive must be force-linked so the boundary stays contiguous.
- **Private-key-read service indicator.** FIPS gates TLS key derivation behind
  `wolfCrypt_SetPrivateKeyReadEnable_fips`; the shell must enable it around the
  TLS 1.3 HKDF calls on the `fips` backend, as `tls13.c` does.

This proves the design does not block `fips`; it is not itself a validated build.
The bundle here is a host (x86-64) FIPS Ready tree, not the H563 operational
environment, and FIPS Ready carries no certificate.
