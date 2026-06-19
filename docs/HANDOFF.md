# Handoff — device testing

This documents what is verified on the development host (Intel x86_64 Mac) and
what still needs target hardware, so the next person/agent can test the
remaining architectures and finish the positioning numbers.

## Status summary

| Area | State |
|---|---|
| TLS 1.3 PSK + cert handshake (ECDSA/RSA-PSS/Ed25519, multi-cert chain) | done, live interop vs OpenSSL + wolfSSL |
| PQC: ML-KEM-768, X25519MLKEM768 hybrid, ML-DSA-65 | done |
| FIPS provider-seam proof (`make fipsproof`) | done vs wolfCrypt v7.0.0 FIPS Ready |
| Approved-mode ECDHE P-256 (`WOLFNANO_FIPS`) | done, interop verified |
| `WOLFNANO_ASM=<arch>` speedup switch | done |
| All-algo benchmark (`make bench`) | done, Intel measured |
| 13 local test suites (`make test`) | green |

All work is committed locally (not pushed). Branch `main`.

## Verified on host vs needs device

| Arch (`WOLFNANO_ASM=`) | Build | Run / measure |
|---|---|---|
| `none` (portable C) | yes | yes (host) |
| `intel` (x86_64) | yes | **yes — measured** (see Benchmarks.md) |
| `thumb2` (Cortex-M33) | yes (cross-compiles from source) | **needs STM32H563 / Cortex-M board** |
| `armv7` (ARMv8-32) | yes (cross-compiles) | needs 32-bit ARM device or QEMU |
| `aarch64` (ARMv8-A) | needs complete toolchain | needs ARM64 device / Apple-Silicon / QEMU |
| `riscv64` | needs toolchain | needs RISC-V board / QEMU |

## What still needs to be done on a device

1. **Cortex-M33 (STM32H563) — the priority.** Build `WOLFNANO_ASM=thumb2`,
   flash, and measure with the DWT cycle counter (I-cache on, no HW crypto
   block, software asm both sides). This is the plan's headline benchmark.
   - Asm-firing canary: cycle counts for AES-GCM / SHA-256 / ECC P-256 must be
     dramatically lower than a `none` (no-asm) Thumb2 build; a tie means a macro
     is wrong / silent C fallback.
2. **mbedTLS head-to-head footprint** on a small Cortex-M part: gc'd,
   minimal-config, same methodology both sides (mbedTLS is at `~/mbedtls`). Pair
   it with the on-device speed run. wolfNano's own size method is in
   [Footprint.md](Footprint.md).
3. **aarch64 / riscv64**: build + run KATs (and speed if measuring) on real
   silicon, or QEMU for correctness only.

## How to build / test each arch

```sh
# host (always available)
make test                      # 13 suites, portable C
make bench                     # all-algo speed: none vs intel
make interop                   # live TLS 1.3 vs OpenSSL + wolfSSL

# cross-compile the floor for a target (build check, no run on host)
make targets                   # all non-host arches, skip if no toolchain
make floor-thumb2              # one arch
```

Override the toolchain per arch with `CC_<arch>=...`, e.g.
`make floor-aarch64 CC_aarch64=/path/to/aarch64-none-elf-gcc`.

### Toolchain notes (this host)
- Complete Arm toolchain: `/Applications/ArmGNUToolchain/14.2.rel1` (has newlib;
  the Makefile auto-detects it for `thumb2`/`armv7`).
- The Homebrew `arm-none-eabi-gcc` lacks newlib (`stdlib.h` missing) — do not
  use it for the floor.
- `aarch64-elf-gcc` is present but its newlib is incomplete here → `floor-aarch64`
  skips. Install a complete `aarch64-none-elf` (or build natively on ARM64).
- No RISC-V toolchain installed → `floor-riscv64` skips.

### QEMU (correctness only, not timing)
`qemu-user` can run cross-built aarch64/armv7/riscv64 binaries to check KATs.
Emulated cycle counts are meaningless — use real silicon for speed.

## Build-system map (for whoever continues)

- `WOLFNANO_ASM=<arch>` (Makefile) → sets `-DWOLFNANO_TARGET_<X>` (macro bundle
  in `wolfnano_target.h`) + the per-arch SP/asm source file list + toolchain.
- Default is lightweight `WOLFSSL_SP_MATH_ALL` (generic, slow ECC); an
  accelerated arch switches to `WOLFSSL_SP_MATH` + `WOLFSSL_HAVE_SP_ECC` + the
  specialized `sp_<arch>.c` (fast). These two are **mutually exclusive** — never
  mix `SP_MATH_ALL` with a specialized SP file.
- Feature flags stay per-target `-DWOLFNANO_*` (see [Macros.md](Macros.md)); no
  `./configure`.

### Gotchas already solved (don't re-discover)
- x86_64 fast ECC needs **both** `WOLFSSL_SP_X86_64` (sp_int.c inline asm) and
  `WOLFSSL_SP_X86_64_ASM` (the specialized `sp_x86_64.c`).
- `USE_INTEL_SPEEDUP` + `WOLFSSL_X86_64_BUILD` re-route SHA/curve25519/ChaCha/
  PQC to external asm (`sha256_asm.S`, `fe_x25519_asm.S`, `chacha_asm.S`,
  `sha3_asm.S`, `wc_mlkem_asm.S`, `wc_mldsa_asm.S`) — all wired in the intel
  bundle.
- Specialized SP backends do P-256 by default; P-384 needs `WOLFSSL_SP_384`
  (set automatically for the accelerated arches in `wolfnano_target.h`).
- `.S` files pull `wolfnano_config.h` via `settings.h`; C declarations there are
  guarded with `#ifndef __ASSEMBLER__`.
