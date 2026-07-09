/* mbedTLS 4.x TLS 1.3 cert server, FED the shared captured ClientHello so the full
 * server handshake links under -flto (the garbage-input stub degenerates to ~3 KB).
 * 4.x delta from mbed_server_fed.c: PSA-only RNG, so no mbedtls_ssl_conf_rng(). */

#include "mbedtls4_config.h"
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include "captured_ch.h"
#include "srv_cert.h"

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

static volatile unsigned char zmask = 0;
static volatile int ch_pos = 0;

static int bio_recv(void* c, unsigned char* b, size_t n)
{
    int avail, k, i;
    (void)c;
    avail = (int)sizeof(g_client_hello) - ch_pos;
    if (avail <= 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    k = (int)n < avail ? (int)n : avail;
    for (i = 0; i < k; i++) {
        b[i] = (unsigned char)(g_client_hello[ch_pos + i] ^ zmask);
    }
    ch_pos += k;
    return k;
}

int main(void)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    int ret;

    psa_crypto_init();
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&key);
    ret = mbedtls_x509_crt_parse_der(&cert, g_srv_cert, sizeof(g_srv_cert));
    ret += mbedtls_pk_parse_key(&key, g_srv_key, sizeof(g_srv_key), NULL, 0);

    ret += mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
              MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    ret += mbedtls_ssl_conf_own_cert(&conf, &cert, &key);
    ret += mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_bio(&ssl, NULL, bio_send, bio_recv, NULL);
    ret += mbedtls_ssl_handshake(&ssl);

    return ret & 0x7f;
}
