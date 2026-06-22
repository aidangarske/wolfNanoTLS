# Testing

wolfNano is built test-first, the way wolfCOSE and wolfIP are: write the failing
test (an RFC vector, a KAT, or an interop handshake) before the code, and judge
every feature on three axes: RFC conformance, speed, and code size.

## Coverage (100%, enforced)

Every wolfNano source file under `src/` is held at **100% line coverage**, the
wolfCOSE bar. `make coverage` (Linux + lcov) builds the suites under `--coverage`
and `scripts/check_coverage.sh` fails if any file listed in `.github/ci/coverage-100.txt`
drops below 100%; the `coverage` workflow runs it on every push and PR. The only
lines excluded are genuinely-unreachable defensive branches (e.g. a `wc_*`
primitive that cannot fail on a validated input, an allocator-failure branch in
a no-allocator build), each marked `/* LCOV_EXCL_LINE */` or
`LCOV_EXCL_START/STOP` with a one-line reason - never reachable code. The
handshake driver (`wn_connect.c`) is covered offline by an in-process
mock-server test (`make mocktest`) that drives a full PSK handshake plus injected
failure modes, so it needs no network. A per-function **stack budget** is also
gated (`make stackcheck`, <= 5 KB/function).

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
| `make keyupdatetest` | post-handshake KeyUpdate "traffic upd" rekey KAT (RFC 8446 4.6.3) |
| `make sessiontest` | application-data session: wn_Send/wn_Recv/wn_Close, NST-skip, KeyUpdate rekey, close_notify, buffer bounds (mock transport, offline) |
| `make tstest` | transcript hash: incremental + non-destructive interim, SHA-256/384 |
| `make rectest` | record protection: seal/open, tamper rejection, sequence binding |
| `make ksharetest` | X25519 key share / ECDHE agreement |
| `make hstest` | end-to-end crypto handshake (ECDHE + schedule + transcript + record) |
| `make rfctest` | RFC 8448 record key/iv KATs (client + application write keys) |
| `make wctest` | wolfSSL's `wolfcrypt/test/test.c` config-trimmed (29 KAT sub-tests) |
| `make wctestpqc` | wolfSSL KATs incl. ML-KEM/ML-DSA/SHAKE (35 sub-tests) |
| `make msgtest` | wire encode/decode primitives |
| `make chtest` / `make shtest` | ClientHello encoder / ServerHello parser (RFC 8448) |
| `make negtest` | malformed-ServerHello rejection (runs under ASan) |
| `make flighttest` | adversarial encrypted-flight ordering gate (out-of-order/duplicate/unknown rejected) |
| `make alerttest` | internal error to RFC 8446 6.2 alert-description mapping |
| `make matrixtest` | data-driven negotiation matrix (cipher x group x PSK/cert) |
| `make alloctrap` | runtime proof: zero heap calls on the handshake path (`--wrap`) |
| `make interop` | **live TLS 1.3 handshakes vs OpenSSL/wolfSSL: PSK (X25519+P-256) + cert** |
| `make certtest` | X.509 cert chain-link verify (ECC + RSA) |
| `make fipsproof` | `WOLFNANO_CRYPTO=fips` seam proof vs a wolfSSL FIPS bundle (see FIPS.md) |
| `make bench` | all-algo speed, portable C vs Intel asm (see Benchmarks.md) |
| `make targets` | cross-compile the floor for every non-host arch (build check) |

`make wctest` reuses wolfSSL's comprehensive crypto test verbatim from the
submodule. Compiled with the wolfNano config, its `#ifdef` guards trim it to
exactly the floor algorithms - **29 KAT sub-tests** (SHA-256/384/512/512-224/256,
HMAC x3, HKDF, PRF, GMAC, AES/192/256/GCM, ECC, X25519, Ed25519, DRBG, ASN);
MD4/MD5/RSA-CBC/DES3 and the rest compile out. `make wctestpqc` adds the
ML-KEM/ML-DSA/SHAKE KATs (**35 sub-tests**). This lifts wolfSSL's authoritative
vectors directly, complementing the wolfNano RFC-vector KATs.

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
P-256 cert (`tests/pki/server/`); the wolfNano client pins it as the trust
anchor: ECDHE handshake, parse the server Certificate, verify the leaf against
the anchor, verify the ECDSA CertificateVerify over the transcript, verify the
server Finished, send the client Finished (preceded by the compat CCS). The
wolfSSL server runs with `-d` (server-auth only; wolfNano does not present a
client cert).

## Application data

After the handshake, `wn_Connect_*_ex` keeps a `wn_Session` and the client
exchanges data with `wn_Send` / `wn_Recv` / `wn_Close`. `make sessiontest`
drives this offline against crafted, peer-encrypted records (mock transport):
app-data round trip, NewSessionTicket skip, KeyUpdate rekey (both
update_not_requested and update_requested), close_notify to `WOLFNANO_E_CLOSED`,
and undersized-buffer rejection. `make interop` adds a **live app-data leg**
against `openssl s_server -rev` (send a line, read the reversed echo, close),
which also exercises the NewSessionTicket-skip path since OpenSSL sends tickets
right after the TLS 1.3 handshake.
