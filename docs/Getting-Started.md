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

## Writing a client

A client completes a handshake into a `wn_Session`, then exchanges application
data and closes. Crypto goes through the `wc_*` seam; transport is two callbacks
you supply (`wn_IoSend` / `wn_IoRecv`), so wolfNano stays socket-agnostic.

```c
wn_Session sess;
byte scratch[8192], buf[512];
word32 got;

/* PSK + ECDHE handshake; keep the session for application data */
rc = wn_Connect_Psk_ex(&sess, &rng, mySend, myRecv, &fd, psk, pskLen,
                       "Client_identity", scratch, sizeof(scratch));

wn_Send(&sess, (const byte*)"hello", 5);   /* encrypt + send one record   */
wn_Recv(&sess, buf, sizeof(buf), &got);    /* read one app-data record    */
wn_Close(&sess);                           /* close_notify + wipe keys    */
```

`scratch` is a caller buffer the session reuses for record framing (no
allocation). `wn_Recv` transparently skips post-handshake NewSessionTicket
records and processes KeyUpdate; it returns `WOLFNANO_E_CLOSED` when the peer
sends close_notify. The handshake-only `wn_Connect_Psk` (no `_ex`) wipes the
keys and returns when you do not need an application-data session.

Build and run the complete example:

```sh
make example
./build/example_client 127.0.0.1 4433
```

## Memory model

The default build is true no-allocator (`WOLFSSL_NO_MALLOC`). During bring-up
you can relax it:

```sh
make host MALLOC=1
```

## Starter configurations

`configs/` holds ready-to-copy `user_settings.h` templates, one per build
profile or device. Copy the one you want to your project as `user_settings.h`
and build with `-DWOLFSSL_USER_SETTINGS`. `make configs-build` compile-tests
every template against the shell.

| Template | Profile | Cortex-M33 `.text` |
|---|---|--:|
| `user_settings_minimal.h` | PSK + ECDHE X25519 (smallest) | 17.6 KB |
| `user_settings_psk_p256.h` | PSK + ECDHE P-256 (broad interop) | 25.2 KB |
| `user_settings_cert.h` | X.509 server-cert client, ECDSA P-256 | 60.8 KB |
| `user_settings_stm32h563.h` | STM32H563 (Cortex-M33 + Thumb2 asm) | device |
| `user_settings_baremetal.h` | generic no-OS MCU (portable C) | device |

The `.text` numbers reproduce from these exact templates with
`sh bench/footprint-clients.sh` (ArmGNU `-Os -flto --gc-sections`, nano specs);
see [Footprint](Footprint.md).

## Entropy

The DRBG is seeded through a pluggable hook, `wn_seed`. The host self-test
provides one in `tests/wn_host_seed.c` using `arc4random_buf`. An integration
supplies its own (a hardware TRNG or a wolfHAL RNG driver) later.
