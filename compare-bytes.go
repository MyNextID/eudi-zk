package main

// func (c *JWTCircuit) Define(api frontend.API) error {
//
// 	// Compute hash of the private payload
//
// 	privatePayloadDigest, err := SHA256(api, c.JWTPayloadJSON)
// 	if err != nil {
// 		return err
// 	}
// 	publicPayloadDigest, err := SHA256(api, c.JWTPayloadPublic)
// 	if err != nil {
// 		return err
// 	}
//
// 	// Compare the digests byte by byte using the Val() method to access the underlying variable
// 	for i := range privatePayloadDigest {
// 		api.AssertIsEqual(privatePayloadDigest[i].Val, publicPayloadDigest[i].Val)
// 	}
//
// 	return nil
// }

// func SHA256(api frontend.API, payload []uints.U8) ([]uints.U8, error) {
//
// 	// Instantiate SHA256
// 	hash, err := sha2.New(api)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// Compute hash of private payload
// 	hash.Write(payload)
// 	digest := hash.Sum()
//
// 	return digest, nil
// }
//
