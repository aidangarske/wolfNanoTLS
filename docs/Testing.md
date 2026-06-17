# Testing

wolfNano is built test-first, the way wolfCOSE and wolfIP are: write the failing
test (an RFC vector, a KAT, or an interop handshake) before the code, and judge
every feature on three axes: RFC conformance, speed, and code size.

## Crypto floor self-test

`tests/floor_test.c` exercises the floor against published vectors and
functional round-trips:

- SHA-256 KAT (FIPS 180-4, "abc")
- HKDF-SHA256 KAT (RFC 5869 test case 1)
- AES-128-GCM KAT (NIST) plus an encrypt/decrypt round-trip
- X25519 ECDH agreement (both directions match)
- ECDSA P-256 and P-384 sign/verify
- Ed25519 sign/verify
- Hash-DRBG init

Run it:

```sh
make host
```

## Zero-allocation check

The floor is compiled to objects and inspected so no translation unit references
`malloc`/`calloc`/`realloc`/`free`. This proves the true-no-allocator property
for the `src` floor statically (independent of any runtime malloc trap).

## Shell test suites (`make test`)

| Target | Covers |
|---|---|
| `make host` | crypto floor KATs (SHA-256, HKDF, AES-GCM, X25519, ECDSA, Ed25519, DRBG) |
| `make kstest` | TLS 1.3 key schedule, full RFC 8448 secret tree (12 KATs) |
| `make tstest` | transcript hash: incremental + non-destructive interim, SHA-256/384 |
| `make rectest` | record protection: seal/open, tamper rejection, sequence binding |
| `make ksharetest` | X25519 key share / ECDHE agreement |
| `make hstest` | end-to-end crypto handshake (ECDHE + schedule + transcript + record) |
| `make wctest` | wolfSSL's own `wolfcrypt/test/test.c`, config-trimmed to the floor |

`make wctest` reuses wolfSSL's comprehensive crypto test verbatim from the
submodule. Compiled with the wolfNano config, its `#ifdef` guards trim it to
exactly the floor algorithms (SHA-2, HMAC, HKDF, PRF, GMAC, AES-GCM, ECC,
X25519, Ed25519, DRBG); MD4/MD5/RSA/DES3/AES-CBC and the rest compile out. This
complements the wolfNano RFC-vector KATs rather than replacing them.

The CVE-dense core (key schedule, transcript) is verified against RFC 8448
vectors first, as planned.

## Still ahead

The wire-level handshake state machine (ClientHello encode, ServerHello /
EncryptedExtensions / Certificate / CertVerify / Finished parse) and live
interop against stock wolfSSL / OpenSSL. A data-driven suite matrix and a
structured `test-pki/` follow with the certificate path.
