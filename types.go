package bls

/*
#include <mcl/curve_type.h>
*/
import "C"

import (
	"fmt"
	"sync"
)

//noinspection GoSnakeCaseUsage,GoNameStartsWithPackageName
const (
	// BN254 -- 254 bit curve
	BN254 = Curve(C.MCL_BN254)

	// BN_SNARK1
	BN_SNARK1 = Curve(C.MCL_BN_SNARK1)

	// BN381_1 -- 382 bit curve 1
	BN381_1 = Curve(C.MCL_BN381_1)

	// BN381_2 -- 382 bit curve 2
	BN381_2 = Curve(C.MCL_BN381_2)

	// BLS12_381
	BLS12_381 = Curve(C.MCL_BLS12_381)
)

var current Curve = -1
var currentMutex sync.RWMutex

func CurrentCurveType() Curve {
	currentMutex.RLock()
	defer currentMutex.RUnlock()
	return current
}

type Curve int8

func (curve Curve) Init() {
	curve.Run(nil)
}

func (curve Curve) Run(fun func()) {
	currentMutex.RLock()
	rlock := true
	defer func() {
		if rlock {
			currentMutex.RUnlock()
		}
	}()

	if current != curve {
		currentMutex.RUnlock()
		rlock = false

		currentMutex.Lock()
		defer currentMutex.Unlock()

		if current != curve {
			err := initCurve(curve)
			if err != nil {
				panic(err)
			}
			current = curve
		}
	}

	if fun != nil {
		fun()
	}
}

func (curve Curve) IsValid() bool {
	return curve == BN254 || curve == BN_SNARK1 || curve == BN381_1 || curve == BN381_2 || curve == BLS12_381
}

func (curve Curve) SecretKeyLength() int {
	if curve == BN254 || curve == BN_SNARK1 || curve == BLS12_381 {
		return 32
	} else if curve == BN381_1 || curve == BN381_2 {
		return 48
	} else {
		panic(fmt.Sprintf("invalid curve `%d`", curve))
	}
}

func (curve Curve) PublicKeyLength() int {
	if curve == BN254 || curve == BN_SNARK1 {
		return 64
	} else if curve == BN381_1 || curve == BN381_2 || curve == BLS12_381 {
		return 96
	} else {
		panic(fmt.Sprintf("invalid curve `%d`", curve))
	}
}

func (curve Curve) SignLength() int {
	if curve == BN254 || curve == BN_SNARK1 {
		return 32
	} else if curve == BN381_1 || curve == BN381_2 || curve == BLS12_381 {
		return 48
	} else {
		panic(fmt.Sprintf("invalid curve `%d`", curve))
	}
}

func (curve Curve) String() string {
	switch curve {
	case BN254:
		return "BN254"
	case BN_SNARK1:
		return "BN_SNARK1"
	case BN381_1:
		return "BN381_1"
	case BN381_2:
		return "BN381_2"
	case BLS12_381:
		return "BLS12_381"
	}
	return fmt.Sprintf("UNKNOWN(%d)", curve)
}
