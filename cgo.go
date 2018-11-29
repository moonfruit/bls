package bls

/*
#cgo CFLAGS: -I${SRCDIR}/include -DMCLBN_FP_UNIT_SIZE=6
#cgo LDFLAGS: -lbls384 -lmcl -lgmp -lstdc++
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux/amd64
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin/amd64
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows/amd64 -static
*/
import "C"
import "unsafe"

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
