/* Combined role wolfNanoTLS: a device that is both TLS 1.3 client and server with
 * X.509 (client verifies a chain, server signs CertificateVerify). Drives
 * wn_Connect_Cert and wn_Accept_Cert so --gc-sections keeps both the verify and
 * sign paths. Size only; stub I/O + seed. */

#include "wn_connect.h"
#include "wn_accept.h"
#include <wolfssl/wolfcrypt/random.h>

#ifndef WN_FP_SCHEME
#define WN_FP_SCHEME 0x0403          /* ecdsa_secp256r1_sha256; 0x0904 = ML-DSA-44 */
#endif

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
static byte cert[2048];
static byte key[2048];

int main(void)
{
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    ret += wn_Connect_Cert(&rng, io_send, io_recv, NULL, cert, (word32)sizeof(cert),
                           scratch, (word32)sizeof(scratch));
    ret += wn_Accept_Cert(&rng, io_send, io_recv, NULL, cert, (word32)sizeof(cert),
                          key, (word32)sizeof(key), WN_FP_SCHEME, scratch,
                          (word32)sizeof(scratch));
    return ret & 0x7f;
}
