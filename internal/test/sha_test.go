package test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/moonfruit/bls"
	"github.com/moonfruit/bls/internal/mbedtls"
	"github.com/moonfruit/bls/internal/openssl"
)

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

	t.Run("openssl256", test(bls.Sha256, openssl.Sha256))
	t.Run("mbedtls256", test(bls.Sha256, mbedtls.Sha256))
	t.Run("openssl512", test(bls.Sha512, openssl.Sha512))
	t.Run("mbedtls512", test(bls.Sha512, mbedtls.Sha512))
}

func BenchmarkSha(b *testing.B) {
	bench := func(f func()) func(b *testing.B) {
		return func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				f()
			}
		}
	}

	b.Run("go256", bench(bls.Run256))
	b.Run("openssl256", bench(openssl.Run256))
	b.Run("mbedtls256", bench(mbedtls.Run256))
	b.Run("go512", bench(bls.Run512))
	b.Run("openssl512", bench(openssl.Run512))
	b.Run("mbedtls512", bench(mbedtls.Run512))
}
