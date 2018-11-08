// +build sha

package bls

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/moonfruit/bls/internal"
)

func TestSha256(t *testing.T) {
	data := make([]byte, 32)

	for i := 0; i < 1000; i++ {
		rand.Read(data)

		hash1 := Sha256(data)
		hash2 := internal.Sha256(data)

		require.Equal(t, hash1, hash2)
	}
}

func TestSha512(t *testing.T) {
	data := make([]byte, 32)

	for i := 0; i < 1000; i++ {
		rand.Read(data)

		hash1 := Sha512(data)
		hash2 := internal.Sha512(data)

		require.Equal(t, hash1, hash2)
	}
}
