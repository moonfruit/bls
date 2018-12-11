package sha

/*
#include <strings.h>
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
	return (*[1<<30]byte)(pointer)[:len:cap]
}
