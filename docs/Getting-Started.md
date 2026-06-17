# Getting Started

wolfNano builds with a plain Makefile and a single `user_settings.h`. There is
no `./configure`.

## Prerequisites

- A C compiler (clang or gcc).
- The wolfSSL submodule, pinned and checked out:

```sh
git clone <wolfNano repo> wolfNano
cd wolfNano
git submodule update --init --depth 1
```

The submodule is sparse-checked-out to the directories wolfNano compiles
(`wolfcrypt/src`, `wolfssl`, `src`). It is consumed unchanged.

## Build and run the crypto floor self-test

The current milestone is the crypto floor. Build and run it locally:

```sh
make host
```

Expected output: every line `PASS`, ending in `ALL PASS (0 failures)`. The test
covers SHA-256, HKDF, AES-GCM, X25519, ECDSA P-256/P-384, Ed25519, and the
Hash-DRBG, against published KATs (FIPS 180-4, RFC 5869, NIST GCM) and
functional round-trips.

## Memory model

The default build is true no-allocator (`WOLFSSL_NO_MALLOC`). During bring-up
you can relax it:

```sh
make host MALLOC=1
```

## Entropy

The DRBG is seeded through a pluggable hook, `wn_seed`. The host self-test
provides one in `tests/wn_host_seed.c` using `arc4random_buf`. An integration
supplies its own (a hardware TRNG or a wolfHAL RNG driver) later.
