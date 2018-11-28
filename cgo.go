package bls

/*
#cgo CFLAGS: -I${SRCDIR}/include -DMCLBN_FP_UNIT_SIZE=6
#cgo LDFLAGS: -lbls384 -lmcl -lgmp -lstdc++
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux/amd64
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin/amd64
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows/amd64 -static

#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"unsafe"
)

var (
	md256 *C.uchar
	md512 *C.uchar
)

//export SHA256
func SHA256(d *C.uchar, n C.size_t, md *C.uchar) *C.uchar {
	if md == nil {
		if md256 == nil {
			md256 = (*C.uchar)(C.malloc(sha256.Size))
		}
		md = md256
	}
	return doHash(sha256.New(), d, n, md)
}

//export SHA512
func SHA512(d *C.uchar, n C.size_t, md *C.uchar) *C.uchar {
	if md == nil {
		if md512 == nil {
			md512 = (*C.uchar)(C.malloc(sha512.Size))
		}
		md = md512
	}
	return doHash(sha512.New(), d, n, md)
}

func doHash(h hash.Hash, d *C.uchar, n C.size_t, md *C.uchar) *C.uchar {
	h.Write(C.GoBytes(unsafe.Pointer(d), C.int(n)))
	p, s := sliceToC(h.Sum(nil))
	C.memcpy(unsafe.Pointer(md), p, s)
	return md
}

func sliceToC(buf []byte) (unsafe.Pointer, C.size_t) {
	length := len(buf)
	if length == 0 {
		return nil, 0
	}
	return unsafe.Pointer(&buf[0]), C.size_t(length)
}

func stringToC(str string) (unsafe.Pointer, C.size_t) {
	length := len(str)
	if length == 0 {
		return nil, 0
	}
	return unsafe.Pointer(C._GoStringPtr(str)), C.size_t(length)
}
