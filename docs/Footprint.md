# Footprint

wolfNanoTLS's whole TLS 1.3 client `.text`, measured on Cortex-M33 (Thumb2,
`arm-none-eabi-gcc -Os -flto -ffunction-sections -fdata-sections
-Wl,--gc-sections` + nano specs, ArmGNU 14.2). Each row builds from a public
`configs/` starter template, so the numbers reproduce from the same
`user_settings.h` a deployment ships.

## Whole TLS 1.3 client (Cortex-M33, measured)

The cert rows show the native `wn_x509` parser (`WOLFNANO_X509_LITE`); the
default backend is wolfSSL `asn.c` (see the X.509 backend section below).

| Client | config | `.text` |
|---|---|--:|
| PSK + ECDHE, X25519 | `user_settings_minimal.h` | 18680 (18.2 KB) |
| PSK + ECDHE, P-256 | `user_settings_psk_p256.h` | 26604 (26.0 KB) |
| PSK + X25519MLKEM768 (PQC) | `user_settings_pqc.h` | 34436 (33.6 KB) |
| cert / X.509, P-256 (`X509_LITE`) | `user_settings_cert.h` | 54396 (53.1 KB) |
| cert / X.509 + ML-DSA-44 (PQC, `X509_LITE`) | `user_settings_cert_mldsa.h` | 69396 (67.8 KB) |

Reproduce: `sh bench/footprint-clients.sh` (wolfNanoTLS column).

The PQC PSK client adds ~15 KB over the classical X25519 client for the
ML-KEM-768 lattice math plus SHA-3/SHAKE (the same `wc_mlkem` code wolfSSL
ships). The ML-DSA-44 cert client (ECDHE P-256 + ML-DSA-44 verify, no RSA) is
the one row built without `-flto`: `wc_mldsa.c` trips an LTO + `--gc-sections`
live-code-removal bug in ArmGNU 14.2, so it slightly over-states versus the
`-flto` rows.

## X.509 backend: native `wn_x509` vs wolfSSL `asn.c`

The cert path defaults to wolfSSL's full `asn.c`/`DecodedCert` (complete,
proven; decodes a wider field set - full DN, certificate policies, name
constraints, CRL/OCSP, ML-DSA leaf keys - decoded, not enforced by the
handshake). `WOLFNANO_X509_LITE` (`make ... X509_LITE=1`) swaps in the smaller
native `wn_x509` parser (hand-written lightweight DER + RFC 5280 subset). Same
client, same crypto floor; only the X.509 backend differs:

| cert client | wolfSSL `asn.c` (default) | native `wn_x509` (`X509_LITE`) | reduction |
|---|--:|--:|--:|
| X.509, P-256 | 63877 (62.4 KB) | 54396 (53.1 KB) | -9481 B (14.8%) |
| X.509 + ML-DSA-44 | 81722 (79.8 KB) | 69396 (67.8 KB) | -12326 B (15.1%) |

Native removes `asn.c`'s reachable cert parser (`DecodeCert` / `GetName` /
`DecodeCertExtensions` / `GetDateInfo` / `wc_*PublicKeyDecode`, ~14-16 KB after
`--gc-sections`) and replaces it with the ~4-5 KB `wn_x509` walker. wolfSSL's own
`asn.c` size options (`WOLFSSL_X509_TINY`, `WOLFSSL_X509_VERIFY_ONLY`,
`IGNORE_NAME_CONSTRAINTS`, `WOLFSSL_NO_ASN_STRICT`) trim only ~3.4% here, because
`--gc-sections` already drops most of what they remove; they keep the ASN
template engine, which is what `wn_x509` replaces wholesale.

Reproduce: `sh bench/footprint-clients.sh` (the "X.509 backend" block).

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
| cert (52 KB) | ~52 KB flash, ~24-40 KB RAM | Cortex-M4/M33 from ~128 KB flash: cloud-IoT endpoints, gateways (STM32L4/U5/H5, nRF53, ESP32) |

The key-exchange floor knob is **X25519** (smallest); set
`WOLFNANO_HAVE_ECDHE_P256` (or `WOLFNANO_FIPS`) for the P-256 build. PQC and asm
add flash on top of the classical floor.

A size comparison against stock/hard-minimized mbedTLS and full wolfSSL is in
[Comparison](Comparison.md).
