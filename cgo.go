package bls

/*
#cgo CFLAGS:-I${SRCDIR}/include -DMCLBN_FP_UNIT_SIZE=6
#cgo LDFLAGS:-lbls384 -lmcl -lcrypto -lgmp -lgmpxx -lstdc++
#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/lib/linux/amd64
#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/lib/darwin/amd64
#cgo windows,amd64 LDFLAGS:-L${SRCDIR}/lib/windows/amd64 -static
#include <bls/bls.h>
*/
import "C"
