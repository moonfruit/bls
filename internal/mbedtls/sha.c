#include <stdlib.h>

#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

static unsigned char *sha256md;
static unsigned char *sha512md;

unsigned char *MBEDTLS_SHA256(const unsigned char *d, size_t n, unsigned char *md) {
    if (md == NULL) {
        if (sha256md == NULL) {
            sha256md = malloc(sizeof(unsigned char) * 32);
        }
        md = sha256md;
    }
    mbedtls_sha256_ret(d, n, md, 0);
    return md;
}

unsigned char *MBEDTLS_SHA512(const unsigned char *d, size_t n, unsigned char *md) {
    if (md == NULL) {
        if (sha512md == NULL) {
            sha512md = malloc(sizeof(unsigned char) * 64);
        }
        md = sha512md;
    }
    mbedtls_sha512_ret(d, n, md, 0);
    return md;
}
