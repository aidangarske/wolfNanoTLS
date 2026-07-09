/* mbedTLS TLS 1.3 PSK client+server DEVICE, size-only. Client half sends first
 * (opaque I/O keeps it reachable); server half is FED the captured ClientHello +
 * matching PSK, so both roles link under -flto. */

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

static volatile int bio_opaque;

static int bio_recv_cli(void* c, unsigned char* b, size_t n)
{
    (void)c;
    bio_opaque = (int)n;
    if ((b != NULL) && (n > 0)) {
        b[0] = (unsigned char)bio_opaque;
    }
    return bio_opaque ? (int)n : MBEDTLS_ERR_SSL_WANT_READ;
}

static volatile unsigned char zmask = 0;
static volatile int ch_pos = 0;

static int bio_recv_srv(void* c, unsigned char* b, size_t n)
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
    mbedtls_ssl_context cssl, sssl;
    mbedtls_ssl_config cconf, sconf;
    int ret;

    psa_crypto_init();
    mbedtls_ssl_init(&cssl); mbedtls_ssl_init(&sssl);
    mbedtls_ssl_config_init(&cconf); mbedtls_ssl_config_init(&sconf);

    ret  = mbedtls_ssl_config_defaults(&cconf, MBEDTLS_SSL_IS_CLIENT,
               MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    ret += mbedtls_ssl_config_defaults(&sconf, MBEDTLS_SSL_IS_SERVER,
               MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&cconf, drng, NULL);
    mbedtls_ssl_conf_rng(&sconf, drng, NULL);
    ret += mbedtls_ssl_conf_psk(&cconf, g_fed_psk, sizeof(g_fed_psk),
               (const unsigned char*)g_fed_id, sizeof(g_fed_id) - 1);
    ret += mbedtls_ssl_conf_psk(&sconf, g_fed_psk, sizeof(g_fed_psk),
               (const unsigned char*)g_fed_id, sizeof(g_fed_id) - 1);
    ret += mbedtls_ssl_setup(&cssl, &cconf);
    ret += mbedtls_ssl_setup(&sssl, &sconf);
    mbedtls_ssl_set_bio(&cssl, NULL, bio_send, bio_recv_cli, NULL);
    mbedtls_ssl_set_bio(&sssl, NULL, bio_send, bio_recv_srv, NULL);
    ret += mbedtls_ssl_handshake(&cssl);
    ret += mbedtls_ssl_handshake(&sssl);

    return ret & 0x7f;
}
