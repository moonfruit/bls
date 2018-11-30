package sha

/*
#cgo CPPFLAGS: -I${SRCDIR}/../include

#include "sha_test.h"
*/
import "C"
import (
	"crypto/sha256"
	"crypto/sha512"
	"unsafe"
)

func Sha256(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha256.Size)
	defer C.free(md)
	C.sha256((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha256.Size)
}

func Sha512(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha512.Size)
	defer C.free(md)
	C.sha512((*C.uchar)(p), s, (*C.uchar)(md))
	return C.GoBytes(md, sha512.Size)
}

func sliceToC(buf []byte) (unsafe.Pointer, C.size_t) {
	length := len(buf)
	if length == 0 {
		return nil, 0
	}
	return unsafe.Pointer(&buf[0]), C.size_t(length)
}

func Run256() {
	C.hash((C.HASH)(C.sha256))
}

func Run512() {
	C.hash((C.HASH)(C.sha512))
}

func GoSha256(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func GoSha512(data []byte) []byte {
	hasher := sha512.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

var data = []byte(C.TESTDATA)

func GoRun256() {
	GoSha256(data)
}

func GoRun512() {
	GoSha512(data)
}
