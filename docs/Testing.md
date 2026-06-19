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
| `make msgtest` | wire encode/decode primitives |
| `make chtest` / `make shtest` | ClientHello encoder / ServerHello parser (RFC 8448) |
| `make interop` | **live TLS 1.3 handshakes vs OpenSSL/wolfSSL: PSK + cert** |
| `make certtest` | X.509 cert chain-link verify (ECC + RSA) |
| `make fipsproof` | `WOLFNANO_CRYPTO=fips` seam proof vs a wolfSSL FIPS bundle (see FIPS.md) |
| `make bench` | all-algo speed, portable C vs Intel asm (see Benchmarks.md) |
| `make targets` | cross-compile the floor for every non-host arch (build check) |

`make wctest` reuses wolfSSL's comprehensive crypto test verbatim from the
submodule. Compiled with the wolfNano config, its `#ifdef` guards trim it to
exactly the floor algorithms (SHA-2, HMAC, HKDF, PRF, GMAC, AES-GCM, ECC,
X25519, Ed25519, DRBG); MD4/MD5/RSA/DES3/AES-CBC and the rest compile out. This
complements the wolfNano RFC-vector KATs rather than replacing them.

The CVE-dense core (key schedule, transcript) is verified against RFC 8448
vectors first, as planned.

## Live interop

`make interop` launches `openssl s_server` (TLS 1.3, external PSK) and a stock
wolfSSL example server, and runs the wolfNano client against each. A green run
means the peer accepted our ClientHello (including the PSK binder), we parsed
its ServerHello, completed ECDHE, decrypted its EncryptedExtensions + Finished,
verified the server Finished MAC, and sent our client Finished. Verified against
**OpenSSL 3.6.2 and wolfSSL**.

The wolfSSL server must be built with PSK + X25519:
`./configure --enable-tls13 --enable-psk --enable-curve25519`. Point
`WOLFSSL_SERVER` at the example server, or it skips cleanly. Requires `openssl`
for the OpenSSL leg.

The cert leg runs against **both OpenSSL and wolfSSL** with a generated ECDSA
P-256 cert (`test-pki/server/`); the wolfNano client pins it as the trust
anchor: ECDHE handshake, parse the server Certificate, verify the leaf against
the anchor, verify the ECDSA CertificateVerify over the transcript, verify the
server Finished, send the client Finished (preceded by the compat CCS). The
wolfSSL server runs with `-d` (server-auth only; wolfNano does not present a
client cert).

## Still ahead

Certificate / Raw-Public-Key authentication (Phase 4 brings X.509), a
data-driven suite matrix, and the structured `test-pki/`.
