package bls

import (
	"crypto/sha256"
	"crypto/sha512"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func goSha256(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func goSha512(data []byte) []byte {
	hasher := sha512.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func TestSha(t *testing.T) {
	data := make([]byte, 32)

	test := func(f1 func([]byte) []byte, f2 func([]byte) []byte) func(t *testing.T) {
		return func(t *testing.T) {
			for i := 0; i < 1000; i++ {
				rand.Read(data)

				hash1 := f1(data)
				hash2 := f2(data)

				require.Equal(t, hash1, hash2)
			}
		}
	}

	t.Run("256", test(hash256, goSha256))
	t.Run("512", test(hash512, goSha512))
}
