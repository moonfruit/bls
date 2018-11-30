#include <cybozu/sha2.hpp>

#include "sha_test.h"

unsigned char *sha256(const unsigned char *data, size_t len, unsigned char *md) {
	cybozu::Sha256().digest(md, 32, data, len);
	return md;
}

unsigned char *sha512(const unsigned char *data, size_t len, unsigned char *md) {
	cybozu::Sha512().digest(md, 64, data, len);
	return md;
}

void hash(HASH h) {
	unsigned char md[64];
	h((const unsigned char *)TESTDATA, 1024, md);
}
