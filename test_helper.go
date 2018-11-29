// +build test

package bls

/*
#include <stdlib.h>

int SHA256_Init(void *c);
int SHA256_Update(void *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, void *c);

int SHA512_Init(void *c);
int SHA512_Update(void *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, void *c);

unsigned char *GO_SHA_256(const unsigned char *data, size_t len, unsigned char *md) {
	int c = 256;

	if (!SHA256_Init(&c)) {
		return NULL;
	}

	if (!SHA256_Update(&c, data, len)) {
		return NULL;
	}

	if (!SHA256_Final(md, &c)) {
		return NULL;
	}

	return md;
}

unsigned char *GO_SHA_512(const unsigned char *data, size_t len, unsigned char *md) {
	int c = 512;

	if (!SHA512_Init(&c)) {
		return NULL;
	}

	if (!SHA512_Update(&c, data, len)) {
		return NULL;
	}

	if (!SHA512_Final(md, &c)) {
		return NULL;
	}

	return md;
}

typedef unsigned char *(*HASH)(const unsigned char *data, size_t len, unsigned char *md);

static void hash(HASH h) {
	const char *d =
		"rfBd67ti3SMtYvSgD6xAV1YU00zampta8Z8S686KLkIZ0PYkL28LTlsVqMNTZyLK"
		"MIFSD3x39MlgPJ1SDZVHnHJPxMKi1tWxu4pQJ82N6GWfOIGTdSWXbRLGAwD2Ikzu"
		"Z6G2pEDzqqm4sncCYry12AuHiK8FDcCc46S5IzoOjgm3v9KyBpNlS63DyhMEXiJe"
		"v7e9bqQKRMnD5MR747KLtiuMzXX1NXjBvzYUgOKWKhDY3j53mPjVIUp08tQjNHJc"
		"aOAGeDZRvcMdGIASmHsVKxASAgqjn0FSPctR0jjTp7hVC5K0eq03EZ1pCcjKTOjl"
		"QFXEFccID1YX4Wjij1noVd13dzrIkvfE8oyNuWFzQt8KaBNgOOduDkdg4imfJmUK"
		"twtISTcIFOAXlck2SNYkNykWvD3z0qHGJSHL8LhjRTFW9VnshBVv3Tw3kxsQTa1k"
		"dqJKFHx0wckLcnxioppr2oEedgLKItAQLW6vCJkFs4MfZG6kMM97T5V7NxXShYDu"
		"bsdgiwmLgoJ5sj4HbvSY8BPUPIWKZDbKqZMgYzVYED5t27w2LXH50iwD89TuWeby"
		"4ZyBSw8nXiIwwx7cAmKCe1VIULPbhZ2KvSbsspv3UY2pbcMTIDZtNqQOIoDr9EMU"
		"gUHiCG4YzMiu4GGDLyhk4iOBtqHxu5V7HvGAkkyrGRRRh8jiDFx3tRBP5AbDn5sP"
		"wHrFB3EBGhKewx5dc0lTBol6Dad44LSxl3qO5CX3Eyhd9U7zfkU865qCozJnsBQ7"
		"oCPQFiRen0xq1ZweTYL6mkaT413GlbvzOnB4nYmGGck1xOJeO0IgytmvTzCRqkHZ"
		"AJPWQUeeUL8VLZewlnSfwiFeROzvcdIhZb4WgePrSHWtTPRopWMWX4f4jlhmxR4C"
		"7bu8N7keVXhgvRO1joUkgC7DbRx0gkZwhGdUwg2qBqnIrNmc55TANjkLZ6x0nwKp"
		"HcsZY7qpi0jmfalfCHa4XOgIU2vsBrivJESeMM5YTd6wdnKIkklblpwrDH9oEOyQ";

	unsigned char md[64];
	h((const unsigned char *)d, 1024, md);
}
*/
import "C"
import (
	"crypto/sha256"
	"crypto/sha512"
)

func Sha256(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha256.Size)
	defer C.free(md)
	C.GO_SHA_256((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha256.Size)
}

func Sha512(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha512.Size)
	defer C.free(md)
	C.GO_SHA_512((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha512.Size)
}

func Run256() {
	C.hash((C.HASH)(C.GO_SHA_256))
}

func Run512() {
	C.hash((C.HASH)(C.GO_SHA_512))
}
