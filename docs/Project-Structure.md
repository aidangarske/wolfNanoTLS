# Project Structure

```
wolfNano/
  Makefile               plain build, no ./configure
  user_settings.h        the one config file (feature selection)
  wolfnano_config.h      WOLFNANO_HAVE_* to wolfSSL macro mapping + size cuts
  wolfnano_target.h      target to asm/SP bundle (PORTABLE_C active; hw deferred)
  COPYING, LICENSING     GPLv3 + commercial, copyright wolfSSL Inc.
  include/wolfnano/       public API (wn_*) and provider seam (added with the shell)
  src/
    shell_slim/          the slim hand-written TLS 1.3 shell (added in the shell phase)
    glue.c               wn_* API to wc_* crypto (added with the shell)
  tests/
    floor_test.c         crypto floor KAT self-test
    wn_host_seed.c       host entropy seed hook for the self-test
  configs/               starter user_settings templates
  examples/              minimal client/server (added later)
  test-pki/              structured test certs/keys (added with X.509)
  bench/                 footprint and timing harnesses (added later)
  docs/                  these wiki pages
  wolfssl/               submodule, pinned + sparse, NEVER modified
```

Only `wolfssl/` comes from upstream and it is never edited. All wolfNano code
lives in the directories above it.
