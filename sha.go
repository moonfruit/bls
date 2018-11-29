package bls

/*
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

var store map[unsafe.Pointer]hash.Hash
var mutex sync.RWMutex

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
	mutex.Lock()
	defer mutex.Unlock()

	if _, ok := store[c]; ok {
		return 0
	}

	if store == nil {
		store = make(map[unsafe.Pointer]hash.Hash)
	}

	store[c] = create()
	return 1
}

func update(c, data unsafe.Pointer, len C.size_t) C.int {
	mutex.RLock()
	defer mutex.RUnlock()

	hasher, ok := store[c]
	if !ok {
		return 0
	}

	hasher.Write(C.GoBytes(data, C.int(len)))
	return 1
}

func final(md *C.uchar, c unsafe.Pointer) C.int {
	mutex.Lock()
	defer mutex.Unlock()

	hasher, ok := store[c]
	if !ok {
		return 0
	}
	delete(store, c)

	p, s := sliceToC(hasher.Sum(nil))
	C.memcpy(unsafe.Pointer(md), p, s)
	return 1
}
