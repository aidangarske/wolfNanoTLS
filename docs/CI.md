# Continuous Integration

wolfNano's CI runs on GitHub Actions. Because wolfNano compiles the **pinned
wolfSSL submodule sources directly** (it never builds wolfSSL via
`./configure`), "testing a wolfSSL version" just means checking out the
submodule at a ref and running wolfNano's Makefile.

## wolfSSL version tracking

The repo carries one committed submodule pin. CI exercises three refs:

| Ref | When | Meaning |
|---|---|---|
| `pinned` | every PR + push | the committed submodule SHA (reproducible baseline) |
| latest `-stable` | nightly | newest `v*-stable` tag (release-drift signal) |
| `master` | nightly | wolfSSL master HEAD (upstream tracking) |

`auto-pin-master.yml` keeps `main` on a recent, frozen, test-passing master
SHA. Nightly it fetches master, and if it differs from the pin, runs the full
suite against it:

- **green** -> bumps the committed pin to that SHA, updates
  `.github/wolfssl-master-known-good.txt`, and closes any open break issue.
- **red** -> leaves the pin alone and opens (or updates) an issue labeled
  `wolfssl-master-break`, assigned to `@aidangarske`, with the failing SHA, the
  upstream short-log since the pin, and a link to the run.

Release branches pin the newest `v*-stable` so shipped artifacts ride QA'd
wolfSSL while `main` rides known-good master.

## Workflows

### Build and test
- `build-test.yml` - `make test` (all suites), {ubuntu, macos} x {gcc, clang}.
- `wolfssl-versions.yml` - the pinned/stable/master matrix.
- `build-matrix.yml` - feature toggles (floor, +MLKEM, +MLDSA, +X509, +RSA,
  +CHACHA, approved-FIPS) each build cleanly; off-state has no undefined refs.
- `arch-build.yml` - host asm bench (none+intel); bare-metal cross-compile of
  the floor (thumb2/aarch64/armv7/riscv64); and a `qemu` job that **runs** the
  suites under qemu-user for arm/aarch64/riscv64 Linux cross-targets (real
  execution, catching endian/word-size/alignment bugs without silicon).
- `minimal-build.yml` - the `bench/min` minimal clients build + size assertion.
- `interop.yml` - `make interop`: wolfNano client vs OpenSSL, wolfSSL, mbedTLS.

### Standards
- `house-style.yml` - no `//`, no em/en-dash, no tabs, no trailing whitespace.
- `empty-brace-scan.yml` - no bare scope blocks.
- `no-alloc-scan.yml` - the malloc/XMALLOC grep (zero-alloc guarantee).
- `no-malloc-runtime.yml` - runtime proof: runs the handshake crypto path under a
  `--wrap` heap trap and asserts zero allocations (Linux/GNU ld only).
- `c89-compliance.yml` - compile the shell `-std=c89 -Werror`.

### Analysis
- `sanitizer.yml` - ASAN/UBSAN of `make test`.
- `semgrep.yml`, `codespell.yml`, `static-analysis.yml` (cppcheck).
- `coverage.yml` - lcov of `make test`.
- `stack-bounds.yml` - `-fstack-usage` report.
- `coverity.yml` - Coverity Scan (token-gated; skips without `COVERITY_TOKEN`).

### Comparison and FIPS
- `compare.yml` - footprint + speed tables vs mbedTLS and wolfSSL in the job
  summary.
- `fips-seam.yml` - `make fipsproof` against the FIPS-Ready bundle.

### Orchestration
- `nightly.yml` - cron 09:00 UTC; runs the heavy reusable workflows.
- `auto-pin-master.yml` - cron 08:00 UTC; the green-gated pin bump above.
- `wiki-sync.yml` - mirrors `docs/**` to the wiki on push to `main`.

## Reusable building blocks
- `.github/actions/wolfssl-checkout` - checkout repo + submodule at a `ref`.
- `.github/actions/setup` - install toolchains and peer build deps.
- `.github/workflows/_discover-wolfssl.yml` - emit the version matrix.

## Running the checks locally

```sh
make test                 # all suites
make interop              # vs OpenSSL / wolfSSL / mbedTLS
make bench                # speed tables (ASM=none vs ASM=intel)
scripts/check_house_style.sh
scripts/empty_brace_scan.sh
scripts/no_alloc_scan.sh
```
