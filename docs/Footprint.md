# Footprint

The crypto floor is the same wolfcrypt objects in wolfNanoTLS and wolfSSL, so it is
not the differentiator. The TLS layer is. Run the comparison with:

```sh
sh bench/footprint.sh
```

## TLS-layer comparison (host clang, -Os)

| | __TEXT bytes | source lines |
|---|---|---|
| wolfNanoTLS slim shell (full TLS 1.3 PSK+ECDHE client) | 8,724 | 1,351 |
| wolfSSL TLS layer (`tls13.c` + `tls.c` only) | 52,318 | (subset) |
| wolfSSL `tls13.c`+`tls.c`+`internal.c`+`ssl.c` | n/a | 96,433 |

The complete wolfNanoTLS TLS 1.3 client (handshake driver, ClientHello/ServerHello,
key schedule, transcript, record protection, key share, wire codec) is roughly
6x smaller in compiled `.text` than just `tls13.c` + `tls.c`, and it omits
`internal.c` and `ssl.c` entirely (the `WOLFSSL` object model), which is the
bulk of the wolfSSL TLS-layer size.

## Crypto floor on Cortex-M33 (cross-compiled, static)

Code size is static, so the on-target crypto floor can be measured on the host
by cross-compiling for Thumb2 and running `size` (no device needed):

```sh
make floor-thumb2     # cross-compile the floor for Cortex-M33
arm-none-eabi-size -t build/thumb2/*.o
```

The default floor (all curves + ASN + both SP backends, pre-`--gc-sections`)
sums to ~250 KB `.text` as an **upper bound**. The shippable number is much
smaller: roughly 40% is optional adders (X.509/ASN ~50 KB, Ed25519 group ops
~49 KB) a minimal PSK/ECDHE-P256 build does not link, and `--gc-sections` drops
the unreferenced remainder. A minimal TLS 1.3 floor (ECDHE-P256 + AES-GCM +
SHA-256 + HKDF + DRBG) lands far lower.

## Notes

- The head-to-head footprint table vs **mbedTLS** (and full wolfSSL) on a small
  Cortex-M part is part of the device/positioning push: it must be a gc'd,
  minimal-config, same-methodology build on both sides to be honest, which pairs
  naturally with the on-device speed benchmark. See [HANDOFF](HANDOFF.md).
- The TLS-layer numbers above are host (x86_64) for relative comparison.
- The comparison is deliberately the TLS layer only; the shared crypto floor is
  excluded because it is byte-identical in both.
- This measures the current shell (key schedule, transcript, record). It grows
  as the handshake state machine lands, but stays a small fraction of the
  wolfSSL TLS layer because the `WOLFSSL`/`internal.c` machinery is never pulled
  in.
