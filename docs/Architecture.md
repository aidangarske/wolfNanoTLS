# Architecture

## Submodule shell, not a fork

wolfNanoTLS does not copy or fork wolfSSL source. It pins wolfSSL as a git
submodule, compiles selected files unchanged, and builds a thin TLS shell on
top. This keeps the crypto bytes identical to upstream without forking.

## Provider seam

The shell calls crypto only through a `wc_*` facade
(`include/wolfnano/wolfnano_crypto.h`, added with the shell). The concrete
provider is chosen at compile time by `WOLFNANO_CRYPTO`:

- `src` (default, GPLv3): a hand-picked list of `wolfcrypt/src/*.c` from the
  submodule, built with `WOLFSSL_NO_MALLOC`. Smallest and deterministic.

The seam is what lets the shell objects link against the crypto backend with
zero shell source changes. Protect that invariant: the shell never calls a
wolfSSL TLS/SSL API or reaches into `internal.c` / `ssl.c` structures.

## X.509 backend (native `wn_x509` vs wolfSSL `asn.c`)

The cert path has two interchangeable, compile-time-selected parsers, so the
handshake pays only for what a deployment needs:

- **wolfSSL `asn.c` (default)**: the full `wc_ParseCert`/`DecodedCert` decoder,
  kept verbatim. It is the complete, battle-tested spec parser (full DN,
  certificate policies, name constraints, CRL/OCSP distribution points, ML-DSA
  leaf keys). It is the default because the cert parser is the handshake's trust
  boundary, and the proven decoder is the safe default. Note this selects the
  *decoder*, not a stronger validation path: the handshake enforces only the
  checks in `wn_VerifyChain` (signature linkage, CA flag, leaf
  keyUsage/serverAuth, hostname/pin, validity). Name constraints, policies, and
  revocation are decoded but not enforced on either backend.
- **native `wn_x509` (`WOLFNANO_X509_LITE`, `make ... X509_LITE=1`)**:
  `src/wn_x509.c`, a hand-written lightweight DER + RFC 5280 subset
  (`wn_X509_Parse` / `wn_X509_VerifySignedBy` / `wn_X509_TimeValid`). The TLV
  layer is lifted from wolfTPM `tpm2_asn.c`; the field walk follows wolfSSL
  `examples/asn1/asn1.c` and the RFC. All signature math stays in `wc_*` via the
  seam; zero allocation, in-place references. It parses exactly the fields a
  pinned-anchor TLS client consumes (tbs range, SPKI/raw key, sig, algorithm
  ids, validity, subject CN, and the basicConstraints/keyUsage/extKeyUsage/SAN
  extensions), fails closed on an unrecognized critical extension, and drops
  `asn.c`'s ~14-16 KB cert parser for ~15% less `.text` (see
  [Footprint](Footprint.md)). It is stricter than `asn.c` on some DER
  encodings and trims scope (no name constraints/policies/CRL/OCSP, capped SAN
  pool) - an opt-in size tier, not a drop-in equal.

Intended scope of the native backend (the pinned-anchor model; use the default
`asn.c` backend for full RFC 5280 path validation):

- Chain linkage is presentation order + per-hop signature + a pinned trust
  anchor; issuer/subject DN name-chaining is not compared (redundant once each
  signature verifies against the next/pinned key).
- `basicConstraints` `pathLenConstraint` is parsed for structure but not enforced.
- A critical `subjectAltName` is honored for its dNSNames; other GeneralName
  forms (iPAddress, URI, ...) are not processed but not rejected, so IP-SAN
  certs still connect. In a pin-only build (`WOLFNANO_X509_HOSTNAME 0`) SAN is
  not parsed at all - the key pin is the identity.
- Duplicate instances of a recognized extension (BC/KU/EKU/SAN) are rejected;
  duplicate unrecognized non-critical extensions are ignored.

`wn_connect.c` selects the backend with a localized `#ifdef`; the differential
test (`make x509diff`) pins native output field-for-field to wolfSSL, and CI
runs the cert suite on both.

There is no `WOLF_CRYPTO_CB` on the default path; it is a fallback adder only.

## True zero allocation

The shell and the `src` floor use no allocator at all (not even a static pool):
all state lives in caller-provided or static buffers. The floor is built with
`WOLFSSL_NO_MALLOC` and verified to carry no `malloc`/`calloc`/`realloc`/`free`
references. The zero-alloc guarantee holds for the whole shell and floor.

## Behavioral subset

wolfNanoTLS is "wolfSSL with features turned off." Interop stays identical to
wolfSSL. The cipher-suite and supported-groups lists are derived from the active
backend, never a fixed array, so the offered lists always match what the
backend supports.

## Clean-room provenance

"Clean-room" here is a provenance rule: copy wolfSSL-family code verbatim (it is
our own code), and write everything that is not wolfSSL-family strictly from the
RFC, never from a third-party source.
