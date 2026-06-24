/* wolfNano minimal-footprint exercise. One scope is selected at build time
 * (FP_AEAD | FP_VERIFY | FP_SIGNVERIFY | FP_HANDSHAKE); the program references
 * exactly that scope's ops so --gc-sections keeps only their code. Results are
 * accumulated into the return value so nothing is dead-stripped as unused.
 * Correctness is irrelevant here; this measures code size only. */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

int wn_fp_seed(unsigned char* output, unsigned int sz)
{
    unsigned int i;
    for (i = 0; i < sz; i++) {
        output[i] = (unsigned char)(i * 7 + 1);
    }
    return 0;
}

int main(void)
{
    int acc = 0;
    byte buf[65];
    byte dg[32];

    XMEMSET(buf, 0x5a, sizeof(buf));
    acc += wc_Sha256Hash(buf, (word32)sizeof(buf), dg);

#if defined(FP_AEAD) || defined(FP_HANDSHAKE)
    {
        Aes aes;
        byte key[16], iv[12], tag[16], ct[64];
        XMEMSET(key, 0x2b, sizeof(key));
        XMEMSET(iv, 0, sizeof(iv));
        acc += wc_AesInit(&aes, NULL, INVALID_DEVID);
        acc += wc_AesGcmSetKey(&aes, key, sizeof(key));
        acc += wc_AesGcmEncrypt(&aes, ct, buf, (word32)sizeof(buf), iv, 12,
                                tag, 16, NULL, 0);
        wc_AesFree(&aes);
    }
#endif

#if defined(FP_HANDSHAKE)
    {
        byte prk[32], okm[16];
        acc += wc_Tls13_HKDF_Extract(prk, NULL, 0, dg, 32, WC_SHA256);
        acc += wc_Tls13_HKDF_Expand_Label(okm, sizeof(okm), prk, 32,
                   (const byte*)"tls13 ", 6, (const byte*)"key", 3, NULL, 0,
                   WC_SHA256);
    }
#endif

#if defined(FP_VERIFY) || defined(FP_SIGNVERIFY) || defined(FP_HANDSHAKE)
    {
        ecc_key k;
        int res = 0;
        byte sig[80];
        word32 sigLen = sizeof(sig);
        acc += wc_ecc_init(&k);
    #if defined(FP_SIGNVERIFY) || defined(FP_HANDSHAKE)
        {
            WC_RNG rng;
            acc += wc_InitRng(&rng);
            acc += wc_ecc_make_key_ex(&rng, 32, &k, ECC_SECP256R1);
            acc += wc_ecc_set_rng(&k, &rng);
        #if defined(FP_SIGNVERIFY)
            acc += wc_ecc_sign_hash(dg, 32, sig, &sigLen, &rng, &k);
        #endif
        #if defined(FP_HANDSHAKE)
            {
                byte sec[32];
                word32 secLen = sizeof(sec);
                acc += wc_ecc_shared_secret(&k, &k, sec, &secLen);
            }
        #endif
            wc_FreeRng(&rng);
        }
    #else
        acc += wc_ecc_import_x963(buf, 65, &k);  /* verify-only: no keygen/RNG */
    #endif
        acc += wc_ecc_verify_hash(sig, sigLen, dg, 32, &res, &k);
        acc += res;
        wc_ecc_free(&k);
    }
#endif

    return acc & 0x7f;
}
