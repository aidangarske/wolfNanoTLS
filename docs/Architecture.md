# Architecture

## Submodule shell, not a fork

wolfNano does not copy or fork wolfSSL source. It pins wolfSSL as a git
submodule, compiles selected files unchanged, and builds a thin TLS shell on
top. This keeps the crypto bytes identical to upstream and keeps FIPS reachable
without forking.

## Provider seam

The shell calls crypto only through a `wc_*` facade
(`include/wolfnano/wolfnano_crypto.h`, added with the shell). The concrete
provider is chosen at compile time by `WOLFNANO_CRYPTO`:

- `src` (default, GPLv3): a hand-picked list of `wolfcrypt/src/*.c` from the
  submodule, built with `WOLFSSL_NO_MALLOC`. Smallest and deterministic.
- `fips` (commercial): links a separately-licensed wolfSSL FIPS bundle supplied
  by the user, under the same unchanged shell. See [FIPS](FIPS.md).

The seam is what lets the same shell objects link against either backend with
zero shell source changes. Protect that invariant: the shell never calls a
wolfSSL TLS/SSL API or reaches into `internal.c` / `ssl.c` structures.

There is no `WOLF_CRYPTO_CB` on the default path; it is a fallback adder only.

## True zero allocation

The shell and the `src` floor use no allocator at all (not even a static pool):
all state lives in caller-provided or static buffers. The floor is built with
`WOLFSSL_NO_MALLOC` and verified to carry no `malloc`/`calloc`/`realloc`/`free`
references. The `fips` backend may allocate internally (its memory model is
frozen at validation); the shell tolerates that, and the zero-alloc guarantee is
asserted for `src` only.

## Behavioral subset

wolfNano is "wolfSSL with features turned off." Interop stays identical to
wolfSSL. The cipher-suite and supported-groups lists are derived from the active
backend, never a fixed array, so a `fips` build never advertises a primitive
outside its boundary.

## Clean-room provenance

"Clean-room" here is a provenance rule: copy wolfSSL-family code verbatim (it is
our own code), and write everything that is not wolfSSL-family strictly from the
RFC, never from a third-party source.
