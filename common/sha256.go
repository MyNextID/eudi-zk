package common

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

func SHA256(api frontend.API, payload []uints.U8) ([]uints.U8, error) {

	// Instantiate SHA256
	hash, err := sha2.New(api)
	if err != nil {
		return nil, err
	}

	// Compute hash of private payload
	hash.Write(payload)
	digest := hash.Sum()

	return digest, nil
}

//
