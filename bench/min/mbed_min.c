/* MbedTLS minimal-footprint exercise: the same scope's ops as wn_min.c, through
 * MbedTLS's API, so --gc-sections keeps only that scope's code. A dummy f_rng
 * avoids pulling the entropy/DRBG modules. Code size only; results ignored. */

#include "mbedtls_config_min.h"
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <string.h>

static int dummy_rng(void* p, unsigned char* out, size_t len)
{
    size_t i;
    (void)p;
    for (i = 0; i < len; i++) {
        out[i] = (unsigned char)(i * 7 + 1);
    }
    return 0;
}

int main(void)
{
    int acc = 0;
    unsigned char buf[64];
    unsigned char dg[32];

    memset(buf, 0x5a, sizeof(buf));
    acc += mbedtls_sha256(buf, sizeof(buf), dg, 0);

#if defined(FP_AEAD) || defined(FP_HANDSHAKE)
    {
        mbedtls_gcm_context gcm;
        unsigned char key[16], iv[12], tag[16], ct[64];
        memset(key, 0x2b, sizeof(key));
        memset(iv, 0, sizeof(iv));
        mbedtls_gcm_init(&gcm);
        acc += mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
        acc += mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(buf),
                   iv, 12, NULL, 0, buf, ct, 16, tag);
        mbedtls_gcm_free(&gcm);
    }
#endif

#if defined(FP_HANDSHAKE)
    {
        unsigned char okm[16];
        const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        acc += mbedtls_hkdf(md, NULL, 0, dg, 32, (const unsigned char*)"key", 3,
                            okm, sizeof(okm));
    }
#endif

#if defined(FP_VERIFY) || defined(FP_SIGNVERIFY) || defined(FP_HANDSHAKE)
    {
        mbedtls_ecp_group grp;
        mbedtls_ecp_point Q;
        mbedtls_mpi r, s, d;

        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&Q);
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_init(&d);
        acc += mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    #if defined(FP_SIGNVERIFY) || defined(FP_HANDSHAKE)
        acc += mbedtls_ecp_gen_keypair(&grp, &d, &Q, dummy_rng, NULL);
        #if defined(FP_SIGNVERIFY)
        acc += mbedtls_ecdsa_sign(&grp, &r, &s, &d, dg, 32, dummy_rng, NULL);
        #endif
        #if defined(FP_HANDSHAKE)
        {
            mbedtls_mpi z;
            mbedtls_mpi_init(&z);
            acc += mbedtls_ecdh_compute_shared(&grp, &z, &Q, &d, dummy_rng, NULL);
            mbedtls_mpi_free(&z);
        }
        #endif
    #endif
        acc += mbedtls_ecdsa_verify(&grp, dg, 32, &Q, &r, &s);

        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&d);
        mbedtls_ecp_point_free(&Q);
        mbedtls_ecp_group_free(&grp);
    }
#endif

    return acc & 0x7f;
}
