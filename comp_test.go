package bls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompatible(t *testing.T) {
	keyBytes := []byte{
		0x2f, 0x4e, 0x60, 0xb6, 0xf7, 0xd0, 0xf2, 0x8, 0x9d, 0x94, 0xfe, 0x6d, 0xb0, 0x6a, 0x34, 0xad,
		0x98, 0xc7, 0x61, 0x9c, 0x45, 0x82, 0xc8, 0x5d, 0xe5, 0x94, 0x6f, 0xaa, 0x4f, 0x11, 0x8f, 0x3e,
	}

	expectedPkeyBytes := []byte{
		0x9e, 0x9e, 0x3d, 0x83, 0xce, 0xc5, 0x60, 0x89, 0xe0, 0x7c, 0x1c, 0xe7, 0x7b, 0x84, 0xc2, 0x83,
		0x5f, 0xd5, 0x9f, 0x5c, 0x4f, 0xba, 0x17, 0x41, 0x97, 0x44, 0xc7, 0x11, 0x30, 0xe1, 0x72, 0x8c,
		0x98, 0xa2, 0x11, 0x2b, 0xd, 0xd3, 0x82, 0xf0, 0xe7, 0x4d, 0x88, 0x81, 0xdd, 0xad, 0x7, 0x13,
		0xc0, 0x4d, 0xb7, 0x20, 0xe6, 0xd2, 0x83, 0xd, 0x6a, 0x4c, 0xab, 0x8b, 0x30, 0x9c, 0xdd, 0x60,
		0x1c, 0xcf, 0x99, 0x62, 0xb2, 0xa1, 0x81, 0x6f, 0xde, 0x4, 0xd6, 0x9, 0xbc, 0x73, 0x49, 0xe9,
		0x93, 0x87, 0x42, 0xf4, 0xb5, 0x4d, 0xd, 0x5e, 0x24, 0x14, 0xd2, 0x1c, 0x95, 0xc6, 0x75, 0x8a,
	}

	data := []byte("abc")

	expectedSignBytes := []byte{
		0xa2, 0x4c, 0x86, 0xad, 0xeb, 0x7a, 0xdb, 0x51, 0x44, 0xc5, 0xad, 0x36, 0xea, 0xba, 0x13, 0xff,
		0xe1, 0x27, 0x7, 0x9c, 0xcd, 0xa9, 0x2, 0x13, 0x81, 0x47, 0xf6, 0x93, 0x76, 0x1b, 0x7b, 0xdf,
		0x44, 0x6, 0x8c, 0x7a, 0x6c, 0x61, 0xc7, 0xcd, 0x4, 0x5, 0x63, 0x5d, 0x59, 0x17, 0x57, 0x83,
	}

	BLS12_381.Init()

	var key SecretKey
	err := key.SetLittleEndian(keyBytes)
	require.NoError(t, err)

	pkey := key.GetPublicKey()
	pkeyBytes := pkey.Serialize()
	assert.Equal(t, expectedPkeyBytes, pkeyBytes)

	sign := key.SignBytes(data)
	signBytes := sign.Serialize()
	assert.Equal(t, expectedSignBytes, signBytes)

	ok := sign.VerifyBytes(pkey, data)
	assert.True(t, ok)
}
