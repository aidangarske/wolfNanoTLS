/* Minimal no-X.509 wolfNanoTLS client: external-PSK + ECDHE (psk_dhe_ke) TLS 1.3
 * handshake. --gc-sections drops the cert/X.509 path, so the binary holds only
 * the PSK+ECDHE code. Size only; stub I/O and seed. */

#include "wn_connect.h"
#include <wolfssl/wolfcrypt/random.h>

int wn_seed(unsigned char* output, unsigned int sz)
{
    unsigned int i;
    for (i = 0; i < sz; i++) {
        output[i] = (unsigned char)(i * 7 + 1);
    }
    return 0;
}

static int io_send(void* ctx, const byte* buf, word32 len)
{
    (void)ctx; (void)buf;
    return (int)len;
}

static int io_recv(void* ctx, byte* buf, word32 len)
{
    (void)ctx; (void)buf; (void)len;
    return 0;
}

static byte scratch[4096];
static byte psk[32];

int main(void)
{
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    ret += wn_Connect_Psk(&rng, io_send, io_recv, NULL, psk, (word32)sizeof(psk),
                          "id", scratch, (word32)sizeof(scratch));
    return ret & 0x7f;
}
