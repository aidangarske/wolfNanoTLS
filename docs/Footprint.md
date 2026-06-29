# Footprint

wolfNanoTLS's whole TLS 1.3 client `.text`, measured on Cortex-M33 (Thumb2,
`arm-none-eabi-gcc -Os -flto -ffunction-sections -fdata-sections
-Wl,--gc-sections` + nano specs, ArmGNU 14.2). Each row builds from a public
`configs/` starter template, so the numbers reproduce from the same
`user_settings.h` a deployment ships.

## Whole TLS 1.3 client (Cortex-M33, measured)

| Client | config | `.text` |
|---|---|--:|
| PSK + ECDHE, X25519 | `user_settings_minimal.h` | 18000 (17.6 KB) |
| PSK + ECDHE, P-256 | `user_settings_psk_p256.h` | 25840 (25.2 KB) |
| PSK + X25519MLKEM768 (PQC) | `user_settings_pqc.h` | 33664 (32.9 KB) |
| cert / X.509, P-256 | `user_settings_cert.h` | 62297 (60.8 KB) |
| cert / X.509 + ML-DSA-44 (PQC) | `user_settings_cert_mldsa.h` | 81166 (79.3 KB) |

Reproduce: `sh bench/footprint-clients.sh` (wolfNanoTLS column).

The PQC PSK client adds ~15 KB over the classical X25519 client for the
ML-KEM-768 lattice math plus SHA-3/SHAKE (the same `wc_mlkem` code wolfSSL
ships). The ML-DSA-44 cert client (ECDHE P-256 + ML-DSA-44 verify, no RSA) is
the one row built without `-flto`: `wc_mldsa.c` trips an LTO + `--gc-sections`
live-code-removal bug in ArmGNU 14.2, so it slightly over-states versus the
`-flto` rows.

## STM32H5 (NUCLEO-H563ZI) — validated on silicon

All five profiles above were run on a real **NUCLEO-H563ZI** as a wolfNanoTLS
client over the [wolfIP](https://github.com/wolfssl/wolfip) TCP/IP stack,
completing a TLS 1.3 handshake (and encrypted echo) against a wolfSSL example
server — so these `.text` figures are what a deployment actually ships and runs,
not just a cross-compile.

| Profile | wolfNanoTLS `.text` | wolfSSL client (same scope) |
|---|--:|--:|
| PSK + ECDHE X25519 | ~17.6 KB | — |
| PSK + ECDHE P-256 | ~25.2 KB | — |
| PSK + X25519MLKEM768 | ~32.9 KB | — |
| cert / X.509 P-256 | ~60.8 KB | **~150 KB** |
| cert / X.509 + ML-DSA-44 | ~79.3 KB | — |

At the X.509 P-256 scope a full **wolfSSL** TLS 1.3 client is **~2.4× larger**
`.text` than wolfNanoTLS — wolfNanoTLS is the smaller client on the H5. Reproduce
the per-profile sizes and the wolfSSL comparison with `sh bench/footprint-h5.sh`
(same toolchain for both columns). On-silicon handshake timings per profile are
in [Benchmarks](Benchmarks.md).

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

## Which devices fit

| Build | flash + RAM budget | device classes |
|---|---|---|
| PSK (17 KB) | ~17 KB flash, ~8-16 KB RAM | Cortex-M0+/M3/M4 from ~32 KB flash: LoRaWAN/NB-IoT/Matter sensors, wearables (STM32L0/L4, nRF52) |
| cert (60 KB) | ~60 KB flash, ~24-40 KB RAM | Cortex-M4/M33 from ~128 KB flash: cloud-IoT endpoints, gateways (STM32L4/U5/H5, nRF53, ESP32) |

The key-exchange floor knob is **X25519** (smallest); set
`WOLFNANO_HAVE_ECDHE_P256` (or `WOLFNANO_FIPS`) for the P-256 build. PQC and asm
add flash on top of the classical floor.

A size comparison against stock/hard-minimized mbedTLS and full wolfSSL is in
[Comparison](Comparison.md).
