package internal

import (
	"crypto/sha256"
	"crypto/sha512"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSha256(t *testing.T) {
	data := make([]byte, 32)

	for i := 0; i < 1000; i++ {
		rand.Read(data)

		hash1 := Sha256(data)
		hash2 := sha256.Sum256(data)

		require.Equal(t, hash1, hash2[:])
	}
}

func TestSha512(t *testing.T) {
	data := make([]byte, 32)

	for i := 0; i < 1000; i++ {
		rand.Read(data)

		hash1 := Sha512(data)
		hash2 := sha512.Sum512(data)

		require.Equal(t, hash1, hash2[:])
	}
}
