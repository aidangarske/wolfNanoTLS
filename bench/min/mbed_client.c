/* mbedTLS whole-deployment footprint harness: a bare-metal TLS 1.3 client that
 * drives the full handshake (mbedtls_ssl_handshake) with stub BIO + dummy RNG,
 * so --gc-sections keeps the TLS 1.3 client path + PSA crypto + X.509 + PK.
 * The binary's .text is the mbedTLS deployment footprint. Size only. */

#include "mbedtls_config_tls.h"
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
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

static int bio_recv(void* c, unsigned char* b, size_t n)
{
    (void)c; (void)b; (void)n;
    return MBEDTLS_ERR_SSL_WANT_READ;
}

int main(void)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    int ret;

    psa_crypto_init();
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&ca);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
              MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, drng, NULL);
    mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
    ret += mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_bio(&ssl, NULL, bio_send, bio_recv, NULL);
    ret += mbedtls_ssl_handshake(&ssl);

    return ret & 0x7f;
}
