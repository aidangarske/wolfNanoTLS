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

## Whole TLS 1.3 client vs MbedTLS / wolfSSL (Cortex-M33, measured)

The real deployment number: a complete TLS 1.3 client linked from source for
Cortex-M33, `arm-none-eabi-gcc -Os -ffunction-sections -fdata-sections
-Wl,--gc-sections`, every library configured to the **same minimal scope**
(ECDHE P-256 + X25519, AES-128-GCM, SHA-2, size knobs; cert build adds X.509 +
ECDSA/RSA verify). `.text` bytes:

| Build | wolfNanoTLS | MbedTLS | wolfSSL | wolfNanoTLS vs MbedTLS |
|---|--:|--:|--:|--:|
| PSK + ECDHE (no X.509) | **31.0 KB** | 80.7 KB | (n/a) | **2.60x smaller** |
| cert / X.509 | **76.9 KB** | 122.1 KB | 162.0 KB | **1.59x smaller** |

Reproduce with `sh bench/footprint-min.sh` (and the `bench/min/` configs +
clients). Notes that keep this honest:

- **Fair config both sides.** MbedTLS's stock default carries 13 curves + ~25
  extra features; stripped to the same scope its PSK client falls 158 -> 81 KB
  and cert 206 -> 122 KB. wolfNanoTLS likewise needed its shell made configurable
  (gate Ed25519 / SHA-384) + a minimal config to drop ~55 KB of Ed25519 group
  ops. Both then measured identically.
- **PSK is the biggest gap (2.6x):** MbedTLS TLS 1.3 mandates the PSA crypto
  subsystem + `ssl_tls.c`, so even a bare PSK client carries ~80 KB of floor;
  wolfNanoTLS's PSK client is the slim shell on wolfCrypt = 31 KB.
- **Raw crypto primitives are ~parity** (MbedTLS's compact bignum/ECP is its
  design strength); the footprint win is the TLS layer / whole stack.
- **Classical numbers.** Enabling PQC or asm adds flash; this is the lean
  classical floor.

### Which devices fit

| Build | flash + RAM budget | device classes |
|---|---|---|
| PSK (31 KB) | ~31 KB flash, ~8-16 KB RAM | Cortex-M0+/M3/M4 from ~64 KB flash: LoRaWAN/NB-IoT/Matter sensors, wearables (STM32L0/L4, nRF52) |
| cert (77 KB) | ~77 KB flash, ~24-40 KB RAM | Cortex-M4/M33 from ~128 KB flash: cloud-IoT endpoints, gateways (STM32L4/U5/H5, nRF53, ESP32) |

The footprint edge lands hardest on small parts: at 31 KB the PSK client fits
where MbedTLS's 81 KB would not.

## Notes

- The crypto-floor and TLS-layer numbers earlier are host (x86_64) for relative
  comparison; the whole-client table above is on-target Cortex-M33.
- The comparison is deliberately the TLS layer only; the shared crypto floor is
  excluded because it is byte-identical in both.
- This measures the current shell (key schedule, transcript, record). It grows
  as the handshake state machine lands, but stays a small fraction of the
  wolfSSL TLS layer because the `WOLFSSL`/`internal.c` machinery is never pulled
  in.
