/* Minimal full-wolfSSL TLS 1.3 cert client+server device, size-only harness (stub I/O + seed).
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
    WOLFSSL_CTX* sctx; WOLFSSL* sssl;
    WOLFSSL_CTX* cctx; WOLFSSL* cssl;
    int ret;

    wolfSSL_Init();
    sctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    wolfSSL_SetIOSend(sctx, sendcb); wolfSSL_SetIORecv(sctx, recvcb);
    sssl = wolfSSL_new(sctx);
    ret = wolfSSL_accept(sssl);

    cctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    wolfSSL_SetIOSend(cctx, sendcb); wolfSSL_SetIORecv(cctx, recvcb);
    cssl = wolfSSL_new(cctx);
    ret += wolfSSL_connect(cssl);
    return ret & 0x7f;
}
