package sha

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
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

	t.Run("256", test(Sha256, GoSha256))
	t.Run("512", test(Sha512, GoSha512))
}

func BenchmarkSha(b *testing.B) {
	bench := func(f func()) func(b *testing.B) {
		return func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				f()
			}
		}
	}

	b.Run("256", bench(Run256))
	b.Run("go256", bench(GoRun256))
	b.Run("512", bench(Run512))
	b.Run("go512", bench(GoRun512))
}

func BenchmarkConcurrentSha(b *testing.B) {
	bench := func(f func()) func(b *testing.B) {
		return func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					f()
				}
			})
		}
	}

	b.Run("256", bench(Run256))
	b.Run("go256", bench(GoRun256))
	b.Run("512", bench(Run512))
	b.Run("go512", bench(GoRun512))
}
