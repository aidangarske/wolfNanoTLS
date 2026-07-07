/* Minimal full-wolfSSL TLS 1.3 cert server, size-only harness (stub I/O + seed).
 * Drives wolfSSL_accept so --gc-sections keeps the TLS 1.3 server + X.509 path. */

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

int main(void)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;

    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    wolfSSL_SetIOSend(ctx, sendcb);
    wolfSSL_SetIORecv(ctx, recvcb);
    ssl = wolfSSL_new(ctx);
    ret = wolfSSL_accept(ssl);
    return ret & 0x7f;
}
