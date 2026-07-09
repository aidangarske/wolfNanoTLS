/* mbedTLS 4.x TLS-side config for the whole-deployment footprint compare:
 * start from the stock default (TLS 1.3 client + X.509) and drop host-only
 * bits (sockets, timing) plus TLS 1.2/DTLS/server and optional extensions,
 * matching the 3.6 bench/min/mbedtls_config_tls.h scope. Crypto primitives
 * are selected in the paired PSA config (mbedtls4_crypto_config.h). */

#ifndef WN_FP_MB4_TLS_CONFIG_H
#define WN_FP_MB4_TLS_CONFIG_H

#include "mbedtls/mbedtls_config.h"

/* host-only I/O / timing */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C

/* TLS 1.3 server only: drop TLS 1.2, server, DTLS */
#undef MBEDTLS_SSL_PROTO_TLS1_2
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_SRTP

/* TLS 1.2 key-exchange selectors (unused without TLS 1.2) */
#undef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED

/* TLS 1.3: ECDHE only (drop PSK modes) */
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_SESSION_TICKETS
#undef MBEDTLS_SSL_TLS1_3_DEFAULT_NEW_SESSION_TICKETS
#undef MBEDTLS_SSL_EARLY_DATA

/* optional TLS extensions / features */
#undef MBEDTLS_SSL_ALPN
#undef MBEDTLS_SSL_RENEGOTIATION
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION
#undef MBEDTLS_SSL_CONTEXT_SERIALIZATION
#undef MBEDTLS_SSL_ENCRYPT_THEN_MAC
#undef MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#undef MBEDTLS_SSL_KEYING_MATERIAL_EXPORT
#undef MBEDTLS_SSL_CACHE_C
#undef MBEDTLS_SSL_TICKET_C

/* X.509: parse/verify DER cert chains only; no write/CSR/CRL */
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C

/* misc host bits / diagnostics */
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_DEBUG_C
#undef MBEDTLS_SSL_DEBUG_ALL
#undef MBEDTLS_ERROR_C
#undef MBEDTLS_VERSION_FEATURES

#endif /* WN_FP_MB4_TLS_CONFIG_H */
