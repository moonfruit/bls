// +build test

package mbedtls

/*
#include <stdlib.h>

typedef unsigned char *(*HASH)(const unsigned char *d, size_t n, unsigned char *md);

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

unsigned char *MBEDTLS_SHA256(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *MBEDTLS_SHA512(const unsigned char *d, size_t n, unsigned char *md);
*/
import "C"
import "unsafe"

const (
	sha256size = 32
	sha512size = 64
)

func Sha256(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha256size)
	defer C.free(md)
	C.MBEDTLS_SHA256((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha256size)
}

func Sha512(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha512size)
	defer C.free(md)
	C.MBEDTLS_SHA512((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha512size)
}

func Run256() {
	C.hash((C.HASH)(C.MBEDTLS_SHA256))
}

func Run512() {
	C.hash((C.HASH)(C.MBEDTLS_SHA512))
}

func sliceToC(buf []byte) (unsafe.Pointer, C.size_t) {
	length := len(buf)
	if length == 0 {
		return nil, 0
	}
	return unsafe.Pointer(&buf[0]), C.size_t(length)
}
