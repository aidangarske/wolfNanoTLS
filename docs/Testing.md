# Testing

wolfNanoTLS is built test-first, the way wolfCOSE and wolfIP are: write the failing
test (an RFC vector, a KAT, or an interop handshake) before the code, and judge
every feature on three axes: RFC conformance, speed, and code size.

## Coverage (100%, enforced)

Every wolfNanoTLS source file under `src/` is held at **100% line coverage**, the
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

The product source is scanned so no translation unit references raw
`malloc`/`calloc`/`realloc`/`free` (the portable `XMALLOC`/`XFREE` macros are
allowed: they are `WOLFSSL_SMALL_STACK`-guarded and compiled out under
`WOLFSSL_NO_MALLOC`). This is the static half; the runtime allocation probe
below proves the no-malloc build allocates nothing.

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
| `make servertest` | PSK server (`wn_Accept_Psk`) vs the real client, all groups (X25519/P-256/hybrid), + send-failure and handshake-only wrapper coverage |
| `make servercerttest` | cert server (`wn_Accept_Cert`) vs the real client: ECDSA P-256/P-384, Ed25519, RSA-PSS SHA-256/384/512, ML-DSA level 2/3/5 |
| `make servernegtest` | adversarial server: arg checks, malformed/oversize ClientHello, IO failures, session-establish polarity |
| `make noalloc-crypto` | runtime proof: zero heap allocations on the crypto path (`--wrap`, no-malloc) |
| `make noalloc-handshake` | runtime proof: zero heap allocations over the full PSK handshake (`--wrap`, no-malloc) |
| `make interop` | **live TLS 1.3 handshakes, both directions (our client and our server) vs OpenSSL/wolfSSL/mbedTLS: PSK (X25519/P-256/hybrid) + cert (ECDSA/Ed25519/RSA/ML-DSA)** |
| `make certtest` | X.509 cert chain-link verify (ECC + RSA) |
| `make x509diff` | native `wn_x509` parse diffed field-for-field vs wolfSSL `wc_ParseCert` over 13 embedded certs |
| `make x509verifytest` | `wn_X509_VerifySignedBy` + `wn_X509_TimeValid` (chain verify vs wolfSSL, tamper reject) |
| `make x509negtest` | crafted adversarial certs (critical-unknown, inner!=outer, truncation) reject |
| `make x509negvectest` | wolfSSL `certs/test/bad-*` malformed vectors, accept/reject parity |
| cert tests `X509_LITE=1` | rebuild the cert suite on the native `wn_x509` backend (default is asn.c; both backends run in CI) |
| `make bench` | all-algo speed, portable C vs Intel asm (see Benchmarks.md) |
| `make targets` | cross-compile the floor for every non-host arch (build check) |
| `make m33mu` | **run** the Thumb2 floor on an emulated Cortex-M33 (STM32H563) under m33mu: KATs, UART, `bkpt #0x7e` pass-gate |

`make wctest` reuses wolfSSL's comprehensive crypto test verbatim from the
submodule. Compiled with the wolfNanoTLS config, its `#ifdef` guards trim it to
exactly the floor algorithms - **29 KAT sub-tests** (SHA-256/384/512/512-224/256,
HMAC x3, HKDF, PRF, GMAC, AES/192/256/GCM, ECC, X25519, Ed25519, DRBG, ASN);
MD4/MD5/RSA-CBC/DES3 and the rest compile out. `make wctestpqc` adds the
ML-KEM/ML-DSA/SHAKE KATs (**35 sub-tests**). This lifts wolfSSL's authoritative
vectors directly, complementing the wolfNanoTLS RFC-vector KATs.

The CVE-dense core (key schedule, transcript) is verified against RFC 8448
vectors first, as planned.

## Live interop

`make interop` launches `openssl s_server` (TLS 1.3, external PSK) and a stock
wolfSSL example server, and runs the wolfNanoTLS client against each. A green run
means the peer accepted our ClientHello (including the PSK binder), we parsed
its ServerHello, completed ECDHE, decrypted its EncryptedExtensions + Finished,
verified the server Finished MAC, and sent our client Finished. Verified against
**OpenSSL 3.6.2 and wolfSSL**.

The wolfSSL server must be built with PSK + X25519:
`./configure --enable-tls13 --enable-psk --enable-curve25519`. Point
`WOLFSSL_SERVER` at the example server, or it skips cleanly. Requires `openssl`
for the OpenSSL leg.

The cert leg runs against **both OpenSSL and wolfSSL** with a generated ECDSA
P-256 cert (`tests/pki/server/`); the wolfNanoTLS client pins it as the trust
anchor: ECDHE handshake, parse the server Certificate, verify the leaf against
the anchor, verify the ECDSA CertificateVerify over the transcript, verify the
server Finished, send the client Finished (preceded by the compat CCS). The
wolfSSL server runs with `-d` (server-auth only; wolfNanoTLS does not present a
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
