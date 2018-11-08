// +build sha

package bls

/*
#include <stdlib.h>

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);
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
	C.SHA256((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha256.Size)
}

func Sha512(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha512.Size)
	defer C.free(md)
	C.SHA512((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha512.Size)
}
