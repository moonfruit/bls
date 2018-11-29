#include <stdlib.h>

#include <openssl/sha.h>

#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#define STATIC_ASSERT(COND, MSG) typedef char static_assertion_##MSG[(COND) ? 1 : -1]

STATIC_ASSERT(sizeof(SHA256_CTX) >= sizeof(mbedtls_sha256_context), not_support_openssl_version);
STATIC_ASSERT(sizeof(SHA512_CTX) >= sizeof(mbedtls_sha512_context), not_support_openssl_version);

#ifdef MBEDTLS_PREFIX
#define PASTER(x, y) x##_##y
#define EVALUATOR(x, y) PASTER(x, y)
#define FUNC(name) EVALUATOR(MBEDTLS_PREFIX, name)
#else
#define FUNC(name) name
#endif

int FUNC(SHA256_Init)(SHA256_CTX *c) {
    mbedtls_sha256_context *ctx = (mbedtls_sha256_context *)c;
    mbedtls_sha256_init(ctx);
    return !mbedtls_sha256_starts_ret(ctx, 0);
}

int FUNC(SHA256_Update)(SHA256_CTX *c, const void *data, size_t len) {
    mbedtls_sha256_context *ctx = (mbedtls_sha256_context *)c;
    return !mbedtls_sha256_update_ret(ctx, data, len);
}

int FUNC(SHA256_Final)(unsigned char *md, SHA256_CTX *c) {
    mbedtls_sha256_context *ctx = (mbedtls_sha256_context *)c;
    int ret = !mbedtls_sha256_finish_ret(ctx, md);
    mbedtls_sha256_free(ctx);
    return ret;
}

int FUNC(SHA512_Init)(SHA512_CTX *c) {
    mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)c;
    mbedtls_sha512_init(ctx);
    return !mbedtls_sha512_starts_ret(ctx, 0);
}

int FUNC(SHA512_Update)(SHA512_CTX *c, const void *data, size_t len) {
    mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)c;
    return !mbedtls_sha512_update_ret(ctx, data, len);
}

int FUNC(SHA512_Final)(unsigned char *md, SHA512_CTX *c) {
    mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)c;
    int ret = !mbedtls_sha512_finish_ret(ctx, md);
    mbedtls_sha512_free(ctx);
    return ret;
}
