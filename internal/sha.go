package internal

/*
#cgo LDFLAGS:-lcrypto
#cgo darwin LDFLAGS:-L/usr/local/opt/openssl/lib
#cgo darwin CFLAGS:-I/usr/local/opt/openssl/include

#include <stdlib.h>

#include <openssl/sha.h>
*/
import "C"
import "unsafe"

const (
	sha256size = C.SHA256_DIGEST_LENGTH
	sha512size = C.SHA512_DIGEST_LENGTH
)

func Sha256(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha256size)
	defer C.free(md)
	C.SHA256((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha256size)
}

func Sha512(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha512size)
	defer C.free(md)
	C.SHA512((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha512size)
}

func sliceToC(buf []byte) (unsafe.Pointer, C.size_t) {
	length := len(buf)
	if length == 0 {
		return nil, 0
	}
	return unsafe.Pointer(&buf[0]), C.size_t(length)
}
