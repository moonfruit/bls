package bls

/*
#cgo CFLAGS:-I${SRCDIR}/include -DMCLBN_FP_UNIT_SIZE=6
#cgo LDFLAGS:-lbls384 -lmcl -lcrypto -lgmp -lgmpxx -lstdc++
#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/lib/darwin/amd64
#include <bls/bls.h>
*/
import "C"
