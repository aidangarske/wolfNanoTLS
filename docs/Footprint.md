# Footprint

The crypto floor is the same wolfcrypt objects in wolfNano and wolfSSL, so it is
not the differentiator. The TLS layer is. Run the comparison with:

```sh
sh bench/footprint.sh
```

## TLS-layer comparison (host clang, -Os)

| | __TEXT bytes | source lines |
|---|---|---|
| wolfNano slim shell (key schedule + transcript + record) | 1,886 | 387 |
| wolfSSL TLS layer (`tls13.c` + `tls.c` only) | 52,318 | (subset) |
| wolfSSL `tls13.c`+`tls.c`+`internal.c`+`ssl.c` | n/a | 96,433 |

wolfNano's TLS layer is roughly 28x smaller in compiled `.text` than just
`tls13.c` + `tls.c`, and it omits `internal.c` and `ssl.c` entirely (the
`WOLFSSL` object model), which is the bulk of the wolfSSL TLS-layer size.

## Notes

- These are host (x86_64) numbers for relative comparison. On-device Cortex-M
  numbers come with the hardware phase.
- The comparison is deliberately the TLS layer only; the shared crypto floor is
  excluded because it is byte-identical in both.
- This measures the current shell (key schedule, transcript, record). It grows
  as the handshake state machine lands, but stays a small fraction of the
  wolfSSL TLS layer because the `WOLFSSL`/`internal.c` machinery is never pulled
  in.
