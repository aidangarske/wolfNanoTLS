/* Minimal full-wolfSSL TLS 1.3 PSK client+server device, size-only harness (stub I/O + seed).
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

static unsigned int cpsk_cb(WOLFSSL* ssl, const char* hint, char* id,
                            unsigned int idmax, unsigned char* key, unsigned int max)
{
    (void)ssl; (void)hint; (void)idmax;
    if (max >= 32) { memset(key, 0, 32); id[0] = 'i'; id[1] = 'd'; id[2] = 0; return 32; }
    return 0;
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
    WOLFSSL_CTX* sctx; WOLFSSL* sssl;
    WOLFSSL_CTX* cctx; WOLFSSL* cssl;
    int ret;

    wolfSSL_Init();
    sctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    wolfSSL_CTX_set_psk_server_callback(sctx, psk_cb);
    wolfSSL_CTX_use_psk_identity_hint(sctx, "id");
    wolfSSL_SetIOSend(sctx, sendcb); wolfSSL_SetIORecv(sctx, recvcb);
    sssl = wolfSSL_new(sctx);
    ret = wolfSSL_accept(sssl);

    cctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    wolfSSL_CTX_set_psk_client_callback(cctx, cpsk_cb);
    wolfSSL_SetIOSend(cctx, sendcb); wolfSSL_SetIORecv(cctx, recvcb);
    cssl = wolfSSL_new(cctx);
    ret += wolfSSL_connect(cssl);
    return ret & 0x7f;
}
