package bls

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"sync"
	"unsafe"
)

var store sync.Map

//export SHA256_Init
//noinspection GoSnakeCaseUsage
func SHA256_Init(c unsafe.Pointer) C.int {
	return initialize(c, sha256.New)
}

//export SHA256_Update
//noinspection GoSnakeCaseUsage
func SHA256_Update(c, data unsafe.Pointer, len C.size_t) C.int {
	return update(c, data, len)
}

//export SHA256_Final
//noinspection GoSnakeCaseUsage
func SHA256_Final(md *C.uchar, c unsafe.Pointer) C.int {
	return final(md, c)
}

//export SHA512_Init
//noinspection GoSnakeCaseUsage
func SHA512_Init(c unsafe.Pointer) C.int {
	return initialize(c, sha512.New)
}

//export SHA512_Update
//noinspection GoSnakeCaseUsage
func SHA512_Update(c, data unsafe.Pointer, len C.size_t) C.int {
	return update(c, data, len)
}

//export SHA512_Final
//noinspection GoSnakeCaseUsage
func SHA512_Final(md *C.uchar, c unsafe.Pointer) C.int {
	return final(md, c)
}

func initialize(c unsafe.Pointer, create func() hash.Hash) C.int {
	store.Store(c, create())
	return 1
}

func update(c, data unsafe.Pointer, len C.size_t) C.int {
	hasher, ok := store.Load(c)
	if !ok {
		return 0
	}

	hasher.(hash.Hash).Write(slice(data, int(len)))
	return 1
}

func final(md *C.uchar, c unsafe.Pointer) C.int {
	obj, ok := store.Load(c)
	if !ok {
		return 0
	}
	store.Delete(c)

	hasher := obj.(hash.Hash)
	hasher.Sum(sliceWithCap(unsafe.Pointer(md), 0, hasher.Size()))
	return 1
}

func slice(pointer unsafe.Pointer, len int) []byte {
	return sliceWithCap(pointer, len, len)
}

func sliceWithCap(pointer unsafe.Pointer, len, cap int) []byte {
	if cap == 0 {
		return nil
	}
	return (*[1 << 30]byte)(pointer)[:len:cap]
}

func hash256(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha256.Size)
	defer C.free(md)

	SHA256_Init(nil)
	SHA256_Update(nil, p, s)
	SHA256_Final((*C.uchar)(md), nil)

	return C.GoBytes(md, sha256.Size)
}

func hash512(data []byte) []byte {
	p, s := sliceToC(data)
	md := C.malloc(sha512.Size)
	defer C.free(md)

	SHA512_Init(nil)
	SHA512_Update(nil, p, s)
	SHA512_Final((*C.uchar)(md), nil)

	return C.GoBytes(md, sha512.Size)
}
