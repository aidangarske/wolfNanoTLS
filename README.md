<div align="center">

<h1>wolfNanoTLS</h1>

**A condensed, TLS 1.3-only embedded TLS library with a selectable
zero-allocation mode, built as a thin shell on top of
[wolfSSL](https://github.com/wolfSSL/wolfssl).**

</div>

## Description and project goals

wolfNanoTLS is a TLS 1.3 client library (with an optional server) and a
selectable zero-allocation mode, built as a thin shell on top of wolfSSL for
resource-constrained embedded systems. It consumes wolfSSL as a pinned git
submodule and never modifies it, reaching crypto only through a small `wc_*`
provider seam.

wolfNanoTLS is a behavioral subset of wolfSSL so it never offers a primitive,
group, suite, or extension that wolfSSL lacks, so interop stays identical to
wolfSSL.

## Features supported

- TLS 1.3 only (RFC 8446).
- External PSK + ECDHE by default. X.509 server-certificate authentication is
  a compile-time adder.
- TLS 1.3 server (`WOLFNANO_SERVER`), a compile-time adder off by default:
  external PSK and X.509 server-cert (ECDSA, Ed25519, RSA-PSS, ML-DSA) across
  all supported groups. Interops both ways with OpenSSL, wolfSSL, and mbedTLS.
- Selectable memory model: plain wolfSSL heap (default), `WOLFSSL_SMALL_STACK`
  (embedded), or true zero dynamic allocation (`WOLFSSL_NO_MALLOC`) proven by a
  runtime allocation probe over the full handshake.
- SNI and full CA chain plus hostname verification, so a named connect reaches
  public HTTPS endpoints.
- Post-quantum ML-KEM-768, X25519MLKEM768 hybrid, and ML-DSA as
  compile-out-able adders.
- Per-feature compile flags: crypto capabilities use wolfSSL's own macros
  (`HAVE_AESGCM`, `HAVE_ECC`, ...), wolfNano policy behind `WOLFNANO_*`. Off
  means no undefined references.
- wolfSSL direct assembly speedups
  (`WOLFNANO_ASM=intel|thumb2|aarch64|armv7|riscv64`).

## Supported algorithms

| Category | Algorithms |                                                                                                                                    
|---|---|                                                                                                                                                    
| Key exchange | ECDHE P-256/P-384, X25519, ML-KEM-768, X25519MLKEM768 (hybrid) |
| Signatures | ECDSA P-256/P-384, Ed25519, RSA-PSS, ML-DSA (client verifies; server signs under `WOLFNANO_SERVER`) |
| AEAD | AES-128/256-GCM, ChaCha20-Poly1305 |
| Hash / KDF | SHA-256, SHA-384, SHA3-256, HMAC, HKDF |

## Build

```sh
git clone --recursive https://github.com/aidangarske/wolfNanoTLS.git
cd wolfNanoTLS
make test
make interop
make bench
```

| Target | Description |
|---|---|
| `make test` | Build and run all unit and KAT suites |
| `make interop` | Live TLS 1.3 handshake vs OpenSSL, wolfSSL, mbedTLS |
| `make bench` | All-algo benchmark, portable C vs Intel asm |
| `make targets` | Cross-compile the floor for every `WOLFNANO_ASM` arch |
| `make clean` | Remove build artifacts |

Select the accelerated backend with
`WOLFNANO_ASM=intel|thumb2|aarch64|armv7|riscv64`. The default `none` is
portable C.

## Usage

```c
wn_Session sess;
byte scratch[8192], buf[512];
word32 got;
int rc;

rc = wn_Connect_Psk_ex(&sess, &rng, mySend, myRecv, &fd, psk, pskLen,
                       "Client_identity", scratch, sizeof(scratch));
if (rc != WOLFNANO_SUCCESS) {
    return rc;
}
if (wn_Send(&sess, (const byte*)"hello", 5) == 0) {
    rc = wn_Recv(&sess, buf, sizeof(buf), &got);
}
wn_Close(&sess);
```

`mySend` and `myRecv` are your transport callbacks. See
[examples/client.c](examples/client.c) (PSK),
[examples/client_cert.c](examples/client_cert.c) (X.509), and
[examples/client_https.c](examples/client_https.c) (live HTTPS GET) for
complete clients.

The server (built with `WOLFNANO_SERVER`) mirrors the API with `wn_Accept_Psk`
and `wn_Accept_Cert`, then the same `wn_Send` / `wn_Recv` / `wn_Close`. See
[examples/server.c](examples/server.c) (PSK) and
[examples/server_cert.c](examples/server_cert.c) (X.509). Build with
`make example-server` / `make example-server-cert`.

## Documentation

Full documentation is in the
[Wiki](https://github.com/aidangarske/wolfNanoTLS/wiki). Footprint and speed
numbers live on the Footprint and Benchmarks pages.

- [Getting Started](https://github.com/aidangarske/wolfNanoTLS/wiki/Getting-Started)
- [Architecture](https://github.com/aidangarske/wolfNanoTLS/wiki/Architecture)
- [Algorithms](https://github.com/aidangarske/wolfNanoTLS/wiki/Algorithms)
- [Macros](https://github.com/aidangarske/wolfNanoTLS/wiki/Macros)
- [Footprint](https://github.com/aidangarske/wolfNanoTLS/wiki/Footprint)
- [Benchmarks](https://github.com/aidangarske/wolfNanoTLS/wiki/Benchmarks)
- [Comparison](https://github.com/aidangarske/wolfNanoTLS/wiki/Comparison)
- [Testing](https://github.com/aidangarske/wolfNanoTLS/wiki/Testing)
- [CI](https://github.com/aidangarske/wolfNanoTLS/wiki/CI)

## License

wolfNanoTLS is free software licensed under
[GPLv3](https://www.gnu.org/licenses/gpl-3.0.html); see [LICENSING](LICENSING)
and [COPYING](COPYING).

Copyright (C) 2006-2026 wolfSSL Inc.

## Support

For commercial licensing or support, contact
[wolfSSL](https://www.wolfssl.com/contact/).
