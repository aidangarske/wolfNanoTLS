#ifndef WN_FP_MB_TLS_SRV_P256_H
#define WN_FP_MB_TLS_SRV_P256_H
#include "mbedtls_config_tls_srv.h"
#undef MBEDTLS_RSA_C
#undef MBEDTLS_PKCS1_V15
#undef MBEDTLS_PKCS1_V21
#undef MBEDTLS_X509_RSASSA_PSS_SUPPORT
#undef MBEDTLS_SHA384_C
#undef MBEDTLS_SHA512_C
#endif
