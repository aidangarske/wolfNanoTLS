# FIPS

wolfNanoTLS runs all of its TLS 1.3 cryptography through wolfCrypt's **FIPS 140-3
validated module** (v5.2.4, CMVP Cert #4718), reached through the provider seam
with zero shell source changes. The TLS protocol shell sits **outside** the
cryptographic boundary, exactly as it does for wolfSSL, OpenSSL, and every other
FIPS deployment: the certificate is issued for the cryptographic module, never
for a TLS library. So the accurate statement is that **wolfNanoTLS operates with a
FIPS 140-3 validated cryptographic module** and performs no cryptography of its
own. It keeps FIPS reachable without forking, the same way wolfSSL itself does.

## Verified against wolfCrypt FIPS 140-3 module v5.2.4 (Cert #4718)

Built and exercised against the licensed commercial module
(`--enable-fips=v5.2.4`, module v5.2.4):

- **In-core integrity self-test (POST) passes** after the standard hash
  regeneration (`fips-hash.sh` patches the per-binary `verifyCore[]` hash,
  rebuild, integrity check reads clean).
- **All CASTs / KATs pass**, including the primitives wolfNanoTLS's handshake uses:
  TLS 1.3 KDF (HKDF Extract/Expand-Label), AES-GCM, SHA-256/384, HMAC, ECC, RSA;
  `testwolfcrypt` exits 0.
- **The seam round-trips through the validated module** (`make fipsproof`):
  `wc_Sha256Hash`, `wc_Tls13_HKDF_Extract`, `wc_Tls13_HKDF_Expand_Label`, and
  `wc_AesGcm` all run through the unchanged `wc_*` header against the module, and
  the in-core integrity / CAST status reads clean.
- **Backend-identical shell:** the same shell sources compiled against the `src`
  and `fips` headers yield the identical logical `wc_*` seam surface; the `fips`
  build only routes each call to its `_fips` boundary wrapper. No shell changes.

This was verified functionally on a development host. FIPS validation is
**operational-environment specific**: Cert #4718 covers Linux operational
environments, so a deployment claiming validation must run on a tested OE for the
active certificate (or be covered by operational equivalence / vendor
affirmation). The CMVP validation itself is wolfSSL's FIPS process, not wolfNanoTLS
code.

## How it works

The validated wolfSSL FIPS module is a separate, commercially-licensed
distribution with its own version lineage. It contains `fips.c`, the in-core
integrity check, and the boundary file set. None of that lives in the public
wolfSSL tree, so wolfNanoTLS cannot produce a validatable module by pinning the
github submodule.

Instead, the shell calls crypto only through the `wc_*` seam, and the backend is
chosen at build time:

- `WOLFNANOTLS_CRYPTO=src`: the public submodule crypto, GPLv3. This is the default.
- `WOLFNANOTLS_CRYPTO=fips`: links a customer-supplied, licensed wolfSSL FIPS bundle
  under the unchanged shell. This build path is commercial, not GPLv3-only.

The goal is that the exact same shell objects link against both backends with
zero shell source changes.

## Honest caveats

- The FIPS module is a licensed artifact the user supplies; wolfNanoTLS does not
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
checks. Point `WOLFNANOTLS_FIPS_DIR` at a built bundle (a FIPS Ready download works
for the seam proof; the licensed validated module is needed for an actual
certificate). Verified against the validated wolfCrypt FIPS 140-3 module v5.2.4
(Cert #4718).

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

This confirms wolfNanoTLS integrates cleanly with the validated module: all TLS 1.3
crypto runs inside the FIPS boundary, the shell stays outside it, and the in-core
integrity self-test passes. Validation remains operational-environment specific
(Cert #4718 covers Linux); a deployment claiming a certificate must run on a
tested OE for that certificate.
