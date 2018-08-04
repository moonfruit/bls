package bls

import (
	"testing"
	"sync"
	"fmt"
)

func TestConcurrent(t *testing.T) {
	var wg sync.WaitGroup

	test := func(curve Curve, index int) {
		wg.Add(1)
		go curve.Run(func() {
			defer wg.Done()
			t.Logf("`%v`,`%v` start", curve, index)
			testWhole(t.Fatal)
			t.Logf("`%v`,`%v` end", curve, index)
		})
	}

	testAll := func(curve Curve) {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			test(curve, i)
		}
	}

	wg.Add(5)
	go testAll(BN254)
	go testAll(BN_SNARK1)
	go testAll(BN381_1)
	go testAll(BN381_2)
	go testAll(BLS12_381)

	wg.Wait()
}

func BenchmarkTypesInit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		BN_SNARK1.Init()
	}
}

func BenchmarkTypesInitCurve(b *testing.B) {
	for i := 0; i < b.N; i++ {
		initCurve(BN_SNARK1)
	}
}

func BenchmarkTypesTS(b *testing.B) {
	var sk *SecretKey
	BN254.Run(func() {
		sk = new(SecretKey).SetByCSPRNG()
	})
	for i := 0; i < b.N; i++ {
		BN254.Run(func() {
			testSignature(realpanic, sk)
		})
	}
}

func BenchmarkTypes(b *testing.B) {
	BN254.Init()
	sk := new(SecretKey).SetByCSPRNG()
	for i := 0; i < b.N; i++ {
		testSignature(realpanic, sk)
	}
}

type mypanic func(args ...interface{})

func realpanic(args ...interface{}) {
	panic(fmt.Sprintln(args))
}

func testWhole(fun mypanic) {
	testSignature(fun, new(SecretKey).SetByCSPRNG())
}

func testSignature(fun mypanic, sk *SecretKey) {
	pk := sk.GetPublicKey()

	m := ""
	sign := sk.Sign(m)

	ok := sign.Verify(pk, m)
	if !ok {
		fun("Verify error")
	}
}
