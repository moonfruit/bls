package sha

/*
#include <string.h>
*/
import "C"
import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"fmt"
	"hash"
	"unsafe"
)

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
	return marshal(c, create())
}

func update(c, data unsafe.Pointer, len C.size_t) C.int {
	hasher, err := unmarshal(c)
	if err != nil {
		return 0
	}

	hasher.Write(C.GoBytes(data, C.int(len)))
	return marshal(c, hasher)
}

func final(md *C.uchar, c unsafe.Pointer) C.int {
	hasher, err := unmarshal(c)
	if err != nil {
		return 0
	}

	p, s := sliceToC(hasher.Sum(nil))
	C.memcpy(unsafe.Pointer(md), p, s)
	return marshal(c, hasher)
}

type hashInfo struct {
	New  func() hash.Hash
	Size int
}

var hashStore = make(map[[4]byte]hashInfo)

func register(create func() hash.Hash) {
	h := create()

	data, _ := h.(encoding.BinaryMarshaler).MarshalBinary()

	var magic [4]byte
	copy(magic[:], data)

	hashStore[magic] = hashInfo{New: create, Size: len(data)}
}

func init() {
	register(sha256.New)
	register(sha512.New)
}

func marshal(c unsafe.Pointer, hasher hash.Hash) C.int {
	bytes, err := hasher.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return 0
	}

	p, s := sliceToC(bytes)
	C.memcpy(c, p, s)
	return 1
}

func unmarshal(c unsafe.Pointer) (hash.Hash, error) {
	var magic [4]byte
	copy(magic[:], C.GoBytes(c, 4))

	info, ok := hashStore[magic]
	if !ok {
		return nil, fmt.Errorf("unknown magic `%v`", magic)
	}

	hasher := info.New()
	if err := hasher.(encoding.BinaryUnmarshaler).UnmarshalBinary(C.GoBytes(c, C.int(info.Size))); err != nil {
		return nil, err
	}

	return hasher, nil
}
