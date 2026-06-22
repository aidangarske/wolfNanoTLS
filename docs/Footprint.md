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

Whole TLS 1.3 client linked from source for Cortex-M33 (X25519, AES-128-GCM,
SHA-256), `arm-none-eabi-gcc -Os -flto -ffunction-sections -fdata-sections
-Wl,--gc-sections` + nano specs (ArmGNU 14.2), with wolfNanoTLS and mbedTLS 3.6
**both hard-minimized to the identical scope**. `.text` bytes:

| Client | wolfNanoTLS | mbedTLS (hard-min) | full wolfSSL | smaller by |
|---|--:|--:|--:|--:|
| PSK + ECDHE, X25519 | **18000** | 42100 | - | 57% |
| PSK + ECDHE, P-256 | **25840** | 50848 | - | 49% |
| cert / X.509, P-256 | **62297** | 101232 | 150913 | 38% |

The wolfNanoTLS column builds from the public `configs/` starter templates
(`user_settings_minimal.h`, `user_settings_psk_p256.h`, `user_settings_cert.h`),
so the numbers reproduce from the same `user_settings.h` a deployment ships.

mbedTLS is given its smallest config too (`MBEDTLS_ECP_FIXED_POINT_OPTIM 0`,
`ECP_WINDOW_SIZE 2`) so the comparison is not inflated in wolfNanoTLS's favor.

Both sides are hard-minimized to **SHA-256 only** (verified: zero SHA-384/512/3,
MD5, SHA-1, DES, ChaCha, CBC/CTR, RSA, ECDSA symbols in either PSK binary).
SHA-256 itself is mandatory in TLS 1.3 (HKDF key schedule, transcript hash,
Finished MAC, PSK binder) and present on both. The remaining wolfNanoTLS vs mbedTLS
gap is architectural: wolfNanoTLS uses specialized `fe_*` X25519 field arithmetic
and direct `wc_*` calls; mbedTLS routes X25519 through its general ECP + bignum
and the mandatory PSA dispatch layer, and links full AES tables. P-256's SP math
is heavier than Curve25519, so both sides grow for P-256. The P-256 PSK client is
interop-verified live against OpenSSL and wolfSSL.

The honest framing:

- **Hard-minimized both sides (the fair number): 34% (PSK) / 40% (cert)
  smaller.** Getting mbedTLS this small required a custom minimal `PSA_WANT_*`
  crypto config (`MBEDTLS_PSA_CRYPTO_CONFIG`) and stripping restartable-ECP,
  SHA-384/512, and the non-GCM AES modes, because mbedTLS 3.6's PSA layer pulls
  in RSA, SHA-1/3, Camellia, DES, ChaCha by default (~80 KB stock PSK).
- **Reproduce:** `sh bench/footprint-clients.sh`. Exact configs:
  `bench/min/mbedtls_config_psk_hardmin.h` + `bench/min/mbedtls_crypto_config_psk.h`
  (mbedTLS), `configs/user_settings_*.h` (wolfNanoTLS).
- **Both harness clients use opaque (volatile) I/O stubs.** A constant-returning
  stub lets LTO prove the handshake aborts after ClientHello and dead-strip the
  rest, understating the footprint; the opaque stub forces the whole reachable
  handshake to stay. Verified: making the mbedTLS bio opaque too moved its PSK
  number by <30 bytes, so neither side is being dead-stripped.
- **Raw crypto primitives are ~parity** (mbedTLS's compact bignum/ECP is its
  design strength); wolfNanoTLS's win is the TLS layer plus whole-stack assembly.
- Full wolfSSL with X.509 is ~147 KB, which is the reason a slim shell exists.
- **Classical numbers.** Enabling PQC or asm adds flash; this is the lean
  classical floor.

### Which devices fit

| Build | flash + RAM budget | device classes |
|---|---|---|
| PSK (17 KB) | ~17 KB flash, ~8-16 KB RAM | Cortex-M0+/M3/M4 from ~32 KB flash: LoRaWAN/NB-IoT/Matter sensors, wearables (STM32L0/L4, nRF52) |
| cert (60 KB) | ~60 KB flash, ~24-40 KB RAM | Cortex-M4/M33 from ~128 KB flash: cloud-IoT endpoints, gateways (STM32L4/U5/H5, nRF53, ESP32) |

The footprint edge lands hardest on small parts: at ~17 KB the X25519 PSK client
fits where even a hard-minimized mbedTLS (41 KB) cannot, and a stock mbedTLS
(~80 KB) is out of the question.

## Notes

- The crypto-floor and TLS-layer numbers earlier are host (x86_64) for relative
  comparison; the whole-client table above is on-target Cortex-M33.
- The comparison is deliberately the TLS layer only; the shared crypto floor is
  excluded because it is byte-identical in both.
- This measures the current shell (key schedule, transcript, record). It grows
  as the handshake state machine lands, but stays a small fraction of the
  wolfSSL TLS layer because the `WOLFSSL`/`internal.c` machinery is never pulled
  in.
