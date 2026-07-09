/* wolfSSL PSK server footprint driver, FED the shared captured ClientHello +
 * matching PSK so the full TLS 1.3 server handshake links - measured identically
 * to the mbedTLS and wolfNanoTLS fed servers. Size only. */

#include <wolfssl/ssl.h>
#include <string.h>
#include "captured_ch.h"

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

static volatile unsigned char zmask = 0;
static volatile int ch_pos = 0;

static int recvcb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int avail, k, i;
    (void)ssl; (void)ctx;
    avail = (int)sizeof(g_client_hello) - ch_pos;
    if (avail <= 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    k = sz < avail ? sz : avail;
    for (i = 0; i < k; i++) {
        buf[i] = (char)(g_client_hello[ch_pos + i] ^ zmask);
    }
    ch_pos += k;
    return k;
}

static unsigned int psk_cb(WOLFSSL* ssl, const char* id, unsigned char* key,
                           unsigned int max)
{
    (void)ssl; (void)id;
    if (max >= sizeof(g_fed_psk)) {
        memcpy(key, g_fed_psk, sizeof(g_fed_psk));
        return (unsigned int)sizeof(g_fed_psk);
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
    wolfSSL_CTX_use_psk_identity_hint(ctx, g_fed_id);
    wolfSSL_SetIOSend(ctx, sendcb);
    wolfSSL_SetIORecv(ctx, recvcb);
    ssl = wolfSSL_new(ctx);
    ret = wolfSSL_accept(ssl);
    return ret & 0x7f;
}
