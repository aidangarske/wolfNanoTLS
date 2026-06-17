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

## Coming with the shell

When the slim TLS 1.3 shell lands, the heaviest coverage goes first at the
rewritten core (transcript-hash KATs, key-schedule RFC vectors, fragmented
record reassembly), diffed against stock wolfSSL as the interop oracle. A
data-driven suite matrix and a structured `test-pki/` follow.
