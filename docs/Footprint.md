# Footprint

The crypto floor is the same wolfcrypt objects in wolfNano and wolfSSL, so it is
not the differentiator. The TLS layer is. Run the comparison with:

```sh
sh bench/footprint.sh
```

## TLS-layer comparison (host clang, -Os)

| | __TEXT bytes | source lines |
|---|---|---|
| wolfNano slim shell (full TLS 1.3 PSK+ECDHE client) | 8,724 | 1,351 |
| wolfSSL TLS layer (`tls13.c` + `tls.c` only) | 52,318 | (subset) |
| wolfSSL `tls13.c`+`tls.c`+`internal.c`+`ssl.c` | n/a | 96,433 |

The complete wolfNano TLS 1.3 client (handshake driver, ClientHello/ServerHello,
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

Whole TLS 1.3 client linked from source for Cortex-M33 (X25519, AES-128-GCM,
SHA-256), `arm-none-eabi-gcc -Os -flto -ffunction-sections -fdata-sections
-Wl,--gc-sections` + nano specs (ArmGNU 14.2), with wolfNano and mbedTLS 3.6
**both hard-minimized to the identical scope**. `.text` bytes:

| Client | wolfNano | mbedTLS (hard-min) | full wolfSSL | smaller by |
|---|--:|--:|--:|--:|
| PSK + ECDHE (no X.509) | **27576** | 42100 | - | 34% |
| cert / X.509 | **61087** | 101232 | 150913 | 40% |

The honest framing:

- **Hard-minimized both sides (the fair number): 34% (PSK) / 40% (cert)
  smaller.** Getting mbedTLS this small required a custom minimal `PSA_WANT_*`
  crypto config (`MBEDTLS_PSA_CRYPTO_CONFIG`) and stripping restartable-ECP,
  SHA-384/512, and the non-GCM AES modes, because mbedTLS 3.6's PSA layer pulls
  in RSA, SHA-1/3, Camellia, DES, ChaCha by default (~80 KB stock PSK).
- **Reproduce:** `sh bench/footprint-clients.sh`. Exact configs:
  `bench/min/mbedtls_config_psk_hardmin.h` + `bench/min/mbedtls_crypto_config_psk.h`
  (mbedTLS), `bench/min/wnc/user_settings.h` (wolfNano).
- **Both harness clients use opaque (volatile) I/O stubs.** A constant-returning
  stub lets LTO prove the handshake aborts after ClientHello and dead-strip the
  rest, understating the footprint; the opaque stub forces the whole reachable
  handshake to stay. Verified: making the mbedTLS bio opaque too moved its PSK
  number by <30 bytes, so neither side is being dead-stripped.
- **Raw crypto primitives are ~parity** (mbedTLS's compact bignum/ECP is its
  design strength); wolfNano's win is the TLS layer plus whole-stack assembly.
- Full wolfSSL with X.509 is ~147 KB, which is the reason a slim shell exists.
- **Classical numbers.** Enabling PQC or asm adds flash; this is the lean
  classical floor.

### Which devices fit

| Build | flash + RAM budget | device classes |
|---|---|---|
| PSK (27 KB) | ~27 KB flash, ~8-16 KB RAM | Cortex-M0+/M3/M4 from ~64 KB flash: LoRaWAN/NB-IoT/Matter sensors, wearables (STM32L0/L4, nRF52) |
| cert (60 KB) | ~60 KB flash, ~24-40 KB RAM | Cortex-M4/M33 from ~128 KB flash: cloud-IoT endpoints, gateways (STM32L4/U5/H5, nRF53, ESP32) |

The footprint edge lands hardest on small parts: at ~27 KB the PSK client fits
where even a hard-minimized mbedTLS (41 KB) is tighter, and a stock mbedTLS
(~80 KB) would not fit at all.

## Notes

- The crypto-floor and TLS-layer numbers earlier are host (x86_64) for relative
  comparison; the whole-client table above is on-target Cortex-M33.
- The comparison is deliberately the TLS layer only; the shared crypto floor is
  excluded because it is byte-identical in both.
- This measures the current shell (key schedule, transcript, record). It grows
  as the handshake state machine lands, but stays a small fraction of the
  wolfSSL TLS layer because the `WOLFSSL`/`internal.c` machinery is never pulled
  in.
