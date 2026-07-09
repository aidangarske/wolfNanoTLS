/* mbedTLS TLS 1.3 PSK server footprint driver that FEEDS a real captured
 * ClientHello, so the server handshake links fully (a garbage-input server stub
 * dead-strips under -flto). Size only. */

#include "mbedtls_config_psk.h"
#include <mbedtls/ssl.h>
#include <psa/crypto.h>
#include "captured_ch.h"

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

/* volatile so -flto cannot constant-fold the ClientHello content and prove the
 * parse result, which would let it dead-strip the rest of the handshake. */
static volatile unsigned char zero_mask = 0;
static volatile size_t ch_pos = 0;

static int bio_recv(void* c, unsigned char* b, size_t n)
{
    size_t avail, k, i;
    (void)c;
    avail = sizeof(g_client_hello) - ch_pos;
    if (avail == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    k = n < avail ? n : avail;
    for (i = 0; i < k; i++) {
        b[i] = (unsigned char)(g_client_hello[ch_pos + i] ^ zero_mask);
    }
    ch_pos += k;
    return (int)k;
}

int main(void)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    int ret;

    psa_crypto_init();
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
              MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, drng, NULL);
    ret += mbedtls_ssl_conf_psk(&conf, g_fed_psk, sizeof(g_fed_psk),
              (const unsigned char*)g_fed_id, sizeof(g_fed_id) - 1);
    ret += mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_bio(&ssl, NULL, bio_send, bio_recv, NULL);
    ret += mbedtls_ssl_handshake(&ssl);

    return ret & 0x7f;
}
