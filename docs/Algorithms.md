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

## Planned adders

| Adder | Algorithm | Status |
|---|---|---|
| `WOLFNANO_MLKEM` | ML-KEM-768, X25519MLKEM768 hybrid | planned |
| `WOLFNANO_MLDSA` | ML-DSA verify | planned |
| `WOLFNANO_X509` | minimal cert path validation | planned |
| `WOLFNANO_HAVE_RSA_VERIFY` | RSA verify for real-world chains | planned |

## Backend boundary note

The offered cipher suites and groups are a function of the active backend. A
`fips` build excludes primitives outside its boundary (for example
ChaCha20-Poly1305 and X25519), and PQC under FIPS is pending, not validated.
