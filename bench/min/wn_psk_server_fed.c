/* wolfNanoTLS PSK server footprint driver, FED the shared captured ClientHello +
 * matching PSK so the full accept handshake links - measured identically to the
 * mbedTLS and wolfSSL fed servers. Size only. */

#include "wn_accept.h"
#include <wolfssl/wolfcrypt/random.h>
#include "captured_ch.h"

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

/* volatile so -flto cannot fold the ClientHello content and dead-strip the rest. */
static volatile byte zmask = 0;
static volatile word32 ch_pos = 0;

static int io_recv(void* ctx, byte* buf, word32 len)
{
    word32 avail, k, i;
    (void)ctx;
    avail = (word32)sizeof(g_client_hello) - ch_pos;
    if (avail == 0) {
        return 0;
    }
    k = len < avail ? len : avail;
    for (i = 0; i < k; i++) {
        buf[i] = (byte)(g_client_hello[ch_pos + i] ^ zmask);
    }
    ch_pos += k;
    return (int)k;
}

static byte scratch[4096];

int main(void)
{
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    ret += wn_Accept_Psk(&rng, io_send, io_recv, NULL, g_fed_psk,
                         (word32)sizeof(g_fed_psk), g_fed_id, scratch,
                         (word32)sizeof(scratch));
    return ret & 0x7f;
}
