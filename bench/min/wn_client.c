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

/* Opaque to the optimizer: a constant return lets LTO prove the handshake
 * aborts after ClientHello and dead-strip the verify path, understating the
 * footprint. The volatile sink forces LTO to keep the whole reachable code. */
static volatile word32 io_opaque;

static int io_recv(void* ctx, byte* buf, word32 len)
{
    (void)ctx;
    io_opaque = len;
    if ((buf != NULL) && (len > 0)) {
        buf[0] = (byte)io_opaque;
    }
    return (int)io_opaque;
}

static byte scratch[12288];
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
