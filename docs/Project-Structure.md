# Project Structure

```
wolfNanoTLS/
  Makefile               plain build, no ./configure
  user_settings.h        the one config file (feature selection)
  wolfnano_config.h      WOLFNANO_HAVE_* to wolfSSL macro mapping + size cuts
  wolfnano_target.h      target to asm/SP bundle (PORTABLE_C active; hw deferred)
  COPYING, LICENSING     GPLv3 + commercial, copyright wolfSSL Inc.
  include/wolfnano/       public API (wn_*) and provider seam (added with the shell)
  src/                   the slim hand-written TLS 1.3 shell (calls only wc_*)
    wn_connect.c         handshake driver (ClientHello -> Finished)
    wn_clienthello.c     ClientHello builder (PSK + cert/ECDHE modes)
    wn_serverhello.c     ServerHello / EncryptedExtensions parser
    wn_keyschedule.c     TLS 1.3 key schedule (RFC 8446 7.1) over the wc_* seam
    wn_transcript.c      handshake transcript hash (incremental, interim digest)
    wn_record.c          TLS 1.3 record protection (AES-GCM, nonce + AAD)
    wn_keyshare.c        X25519 / ECDHE key share
    wn_hybrid.c          X25519MLKEM768 hybrid key share
    wn_msg.c             wire encode/decode primitives
    wn_x509.c            lightweight X.509 v3 parser + verify glue (opt-in size
                         tier via WOLFNANO_X509_LITE; default backend is asn.c)
  tests/
    floor_test.c         crypto floor KAT self-test
    wn_host_seed.c       host entropy seed hook for the self-test
    pki/                 structured test certs/keys (server + chain)
  configs/               starter user_settings templates
  examples/              minimal client/server (added later)
  bench/                 footprint and timing harnesses
  docs/                  these wiki pages
  wolfssl/               submodule, pinned + sparse, NEVER modified
```

Only `wolfssl/` comes from upstream and it is never edited. All wolfNanoTLS code
lives in the directories above it.
