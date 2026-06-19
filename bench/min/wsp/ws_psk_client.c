/* Minimal full-wolfSSL TLS 1.3 PSK client, size-only harness. */

#include <wolfssl/ssl.h>

int wn_fp_seed(unsigned char* output, unsigned int sz)
{
    unsigned int i;
    for (i = 0; i < sz; i++) {
        output[i] = (unsigned char)(i * 7 + 1);
    }
    return 0;
}

static int sendcb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)buf; (void)ctx;
    return sz;
}

static int recvcb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)buf; (void)sz; (void)ctx;
    return WOLFSSL_CBIO_ERR_WANT_READ;
}

static unsigned int psk_cb(WOLFSSL* ssl, const char* hint, char* identity,
    unsigned int id_max, unsigned char* key, unsigned int key_max,
    const char** ciphersuite)
{
    unsigned int i;
    (void)ssl; (void)hint; (void)ciphersuite;
    if (id_max > 2) {
        identity[0] = 'i';
        identity[1] = '\0';
    }
    for (i = 0; i < 32 && i < key_max; i++) {
        key[i] = (unsigned char)i;
    }
    return 32;
}

int main(void)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;

    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    wolfSSL_CTX_set_psk_client_tls13_callback(ctx, psk_cb);
    wolfSSL_SetIOSend(ctx, sendcb);
    wolfSSL_SetIORecv(ctx, recvcb);
    ssl = wolfSSL_new(ctx);
    ret = wolfSSL_connect(ssl);
    return ret & 0x7f;
}
