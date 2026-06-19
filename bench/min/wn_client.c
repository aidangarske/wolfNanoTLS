/* Whole-deployment footprint harness: a bare-metal TLS 1.3 client entry point
 * that drives the full wolfNanoTLS cert handshake (wn_Connect_Cert) with stub I/O
 * and seed. Links the floor crypto + the whole shell; --gc-sections keeps only
 * the handshake's reachable code, so the binary's .text is the real deployment
 * footprint. Correctness is irrelevant; this measures size. */

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

static byte scratch[8192];
static byte anchor[512];

int main(void)
{
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    ret += wn_Connect_Cert(&rng, io_send, io_recv, NULL, anchor,
                           (word32)sizeof(anchor), scratch, (word32)sizeof(scratch));
    return ret & 0x7f;
}
