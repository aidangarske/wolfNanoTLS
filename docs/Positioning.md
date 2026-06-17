# Positioning

Where wolfNano sits relative to its neighbors.

| | wolfSSL | wolfTLS | wolfNano |
|---|---|---|---|
| Form | full library | trimmed fork (distro) | submodule shell |
| Protocols | SSL 3.0 to TLS 1.3, DTLS | TLS 1.2/1.3, DTLS | TLS 1.3 only |
| Memory | configurable | configurable | true no-allocator |
| Footprint | full | reduced | smallest |
| FIPS | validated module | bring-your-own | bring-your-own via seam |

- **wolfSSL** is the full, general-purpose library and the upstream wolfNano
  pins and consumes unchanged.
- **wolfTLS** is a broad modern-TLS fork (TLS 1.2 plus 1.3, DTLS, one library).
- **wolfNano** is the ultra-light, TLS 1.3-only, true zero-allocation shell for
  the smallest constrained devices. It is complementary to wolfTLS, not a
  competitor: different scope, different memory model.

The target story: smaller than mbedTLS on a constrained device while keeping
wolfSSL's assembly speedups and adding PQC, with FIPS reachable through the
provider seam. The headline comparison (size and handshake speed versus full
wolfSSL and mbedTLS) is produced by the benchmark phase.
