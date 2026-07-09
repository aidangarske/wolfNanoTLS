/* mbedTLS TLS 1.3 cert client+server DEVICE, size-only. The client half sends
 * first (stays reachable via opaque I/O); the server half is FED the captured
 * ClientHello + a real embedded cert so its handshake links too, so the binary
 * keeps BOTH roles under -flto (a garbage-fed server half degenerates). */

#include "mbedtls_config_tls.h"
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
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    int ret;

    psa_crypto_init();
    mbedtls_ssl_init(&cssl); mbedtls_ssl_init(&sssl);
    mbedtls_ssl_config_init(&cconf); mbedtls_ssl_config_init(&sconf);
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&key);
    ret  = mbedtls_x509_crt_parse_der(&cert, g_srv_cert, sizeof(g_srv_cert));
    ret += mbedtls_pk_parse_key(&key, g_srv_key, sizeof(g_srv_key), NULL, 0, drng, NULL);

    ret += mbedtls_ssl_config_defaults(&cconf, MBEDTLS_SSL_IS_CLIENT,
               MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    ret += mbedtls_ssl_config_defaults(&sconf, MBEDTLS_SSL_IS_SERVER,
               MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&cconf, drng, NULL);
    mbedtls_ssl_conf_rng(&sconf, drng, NULL);
    mbedtls_ssl_conf_ca_chain(&cconf, &cert, NULL);
    ret += mbedtls_ssl_conf_own_cert(&sconf, &cert, &key);
    ret += mbedtls_ssl_setup(&cssl, &cconf);
    ret += mbedtls_ssl_setup(&sssl, &sconf);
    mbedtls_ssl_set_bio(&cssl, NULL, bio_send, bio_recv_cli, NULL);
    mbedtls_ssl_set_bio(&sssl, NULL, bio_send, bio_recv_srv, NULL);
    ret += mbedtls_ssl_handshake(&cssl);
    ret += mbedtls_ssl_handshake(&sssl);

    return ret & 0x7f;
}
