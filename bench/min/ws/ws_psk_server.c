/* Minimal full-wolfSSL TLS 1.3 PSK server, size-only harness (stub I/O + seed).
 * Drives wolfSSL_accept with a PSK callback so --gc-sections keeps the TLS 1.3
 * server + PSK+ECDHE path. */

#include <wolfssl/ssl.h>
#include <string.h>

sword64 TimeNowInMilliseconds(void) { return 0; }

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

static unsigned int psk_cb(WOLFSSL* ssl, const char* id, unsigned char* key,
                           unsigned int max)
{
    (void)ssl; (void)id;
    if (max >= 32) {
        memset(key, 0, 32);
        return 32;
    }
    return 0;
}

int main(void)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;

    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    wolfSSL_CTX_set_psk_server_callback(ctx, psk_cb);
    wolfSSL_CTX_use_psk_identity_hint(ctx, "id");
    wolfSSL_SetIOSend(ctx, sendcb);
    wolfSSL_SetIORecv(ctx, recvcb);
    ssl = wolfSSL_new(ctx);
    ret = wolfSSL_accept(ssl);
    return ret & 0x7f;
}
