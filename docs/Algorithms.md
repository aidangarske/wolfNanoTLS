# Algorithms

## Crypto floor (current)

The minimal set required for a TLS 1.3 handshake, all building and passing KATs
locally:

| Area | Algorithm |
|---|---|
| Hash | SHA-256, SHA-384/512 |
| KDF | HKDF (HMAC-based) |
| AEAD | AES-128/256-GCM |
| Key exchange | ECDHE P-256/P-384, X25519 |
| Signature | ECDSA P-256/P-384, Ed25519 |
| RNG | Hash-DRBG, seeded via the `wn_seed` hook |

ChaCha20-Poly1305 is available behind `WOLFNANO_HAVE_CHACHA`.

## PQC adders (done)

| Adder | Algorithm | Status |
|---|---|---|
| `WOLFNANO_MLKEM` | ML-KEM-768 (KEM) | done, allocation-free |
| `WOLFNANO_MLKEM` | X25519MLKEM768 hybrid key share (group 0x11ec) | done, client+server agreement |
| `WOLFNANO_MLDSA` | ML-DSA-65 verify (no-malloc) | done, allocation-free |
| `WOLFNANO_MLDSA` + `WOLFNANO_MLDSA_SIGN` | ML-DSA-65 keygen/sign | done (needs working memory) |

ML-KEM-768 and ML-DSA-65 verify are both **allocation-free** under
`WOLFSSL_NO_MALLOC`. ML-DSA keygen/sign (server side) needs working memory, so
it is gated behind `WOLFNANO_MLDSA_SIGN`. The hybrid concatenation is ML-KEM
component first, then X25519 (draft-kwiatkowski-tls-ecdhe-mlkem).

## Cert auth (Phase 4, in progress)

| Adder | Capability | Status |
|---|---|---|
| `WOLFNANO_X509` | parse cert + verify signature against issuer key | done |
| `WOLFNANO_HAVE_RSA_VERIFY` | RSA-signed chains | done |
| handshake Certificate / CertVerify | cert-based (non-PSK) handshake | done, live vs OpenSSL + wolfSSL |
| CertVerify schemes: ECDSA P-256/384, RSA-PSS SHA-256/384, Ed25519 | | done, all live vs OpenSSL + wolfSSL |
| multi-cert chain validation (leaf -> intermediate -> pinned root) | | done, live vs OpenSSL |
| validity-time + name constraint checks | | planned |

**Memory note:** unlike the floor and the PSK/RPK handshake (which are true
no-allocator), X.509 cert parsing uses a `DecodedCert` and needs working memory.
`WOLFNANO_X509` therefore requires a heap or a `WOLFSSL_STATIC_MEMORY` pool;
it is not part of the true-no-allocator guarantee.

## Backend boundary note

The offered cipher suites and groups are a function of the active backend. A
`fips` build excludes primitives outside its boundary (for example
ChaCha20-Poly1305 and X25519), and PQC under FIPS is pending, not validated.
