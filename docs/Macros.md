# Macros

Configuration lives in `user_settings.h`, which selects `WOLFNANO_HAVE_*`
features and includes `wolfnano_target.h` (asm/SP bundle) and
`wolfnano_config.h` (which maps the selections to real wolfSSL macros and
applies the standing size cuts).

## Feature selection (`WOLFNANO_HAVE_*`)

| Flag | Enables | wolfSSL macro(s) |
|---|---|---|
| `WOLFNANO_HAVE_SHA256` | SHA-256 (default on) | default; `NO_SHA256` drops it |
| `WOLFNANO_HAVE_SHA384` | SHA-384/512 | `WOLFSSL_SHA384`, `WOLFSSL_SHA512` |
| `WOLFNANO_HAVE_HKDF` | HKDF (TLS 1.3 key schedule) | `HAVE_HKDF` |
| `WOLFNANO_HAVE_AESGCM` | AES-GCM | `HAVE_AESGCM` |
| `WOLFNANO_HAVE_CHACHA` | ChaCha20-Poly1305 | `HAVE_CHACHA`, `HAVE_POLY1305` |
| `WOLFNANO_HAVE_ECC` | ECDHE + ECDSA (P-256) | `HAVE_ECC`, `ECC_USER_CURVES` |
| `WOLFNANO_HAVE_ECC384` | adds P-384 | `HAVE_ECC384` |
| `WOLFNANO_HAVE_CURVE25519` | X25519 | `HAVE_CURVE25519` |
| `WOLFNANO_HAVE_ED25519` | Ed25519 | `HAVE_ED25519` (pulls SHA-512) |

When a feature is off, the build has no undefined references for it.

## Backend selection

- `WOLFNANO_CRYPTO=src` (default): submodule crypto, GPLv3.
- `WOLFNANO_CRYPTO=fips`: customer-supplied FIPS bundle (see [FIPS](FIPS.md)).

## Build toggles

- `MALLOC=1`: relax the true-no-allocator bar during bring-up
  (`-DWOLFNANO_ALLOW_MALLOC`).
- `WOLFNANO_TARGET_PORTABLE_C`: the active local target (mac/linux). The
  hardware/asm target in `wolfnano_target.h` is deferred.

## Standing size cuts

Always applied in `wolfnano_config.h`: no old TLS, no MD5/SHA-1/DES3/RC4/DSA,
no RSA/DH, no PWDBASED/PKCS12, single-threaded, no filesystem, no error
strings. Cert-time validation (`NO_ASN_TIME`) stays off until the X.509 adder,
which brings a time hook.
