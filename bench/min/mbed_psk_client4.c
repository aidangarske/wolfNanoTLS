/* mbedTLS 4.x minimal PSK (+ECDHE) TLS 1.3 client, no X.509: size-only harness.
 * 4.x delta from bench/min/mbed_psk_client.c: RNG is PSA-only, so the removed
 * mbedtls_ssl_conf_rng() call is dropped; the external RNG callback stays. */

#include "mbedtls4_config_psk.h"
#include <mbedtls/ssl.h>
#include <psa/crypto.h>

static int drng(void* p, unsigned char* out, size_t n)
{
    size_t i;
    (void)p;
    for (i = 0; i < n; i++) {
        out[i] = (unsigned char)(i * 7 + 1);
    }
    return 0;
}

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t* ctx,
    uint8_t* output, size_t output_size, size_t* output_length)
{
    (void)ctx;
    drng(NULL, output, output_size);
    *output_length = output_size;
    return PSA_SUCCESS;
}

static int bio_send(void* c, const unsigned char* b, size_t n)
{
    (void)c; (void)b;
    return (int)n;
}

/* Opaque to the optimizer so LTO cannot prove an early WANT_READ abort and
 * dead-strip later handshake code (kept symmetric with the wolfNanoTLS harness). */
static volatile int bio_opaque;

static int bio_recv(void* c, unsigned char* b, size_t n)
{
    (void)c;
    bio_opaque = (int)n;
    if ((b != NULL) && (n > 0)) {
        b[0] = (unsigned char)bio_opaque;
    }
    return bio_opaque ? (int)n : MBEDTLS_ERR_SSL_WANT_READ;
}

int main(void)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    static const unsigned char psk[32];
    static const unsigned char id[] = "id";
    int ret;

    psa_crypto_init();
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
              MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    ret += mbedtls_ssl_conf_psk(&conf, psk, sizeof(psk), id, sizeof(id) - 1);
    ret += mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_bio(&ssl, NULL, bio_send, bio_recv, NULL);
    ret += mbedtls_ssl_handshake(&ssl);

    return ret & 0x7f;
}
