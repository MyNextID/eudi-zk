package api

import (
	"github.com/consensys/gnark/std/math/uints"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
)

const (
	BYTE_SIZE32     = 32
	BYTE_SIZE64     = 64
	BYTE_SIZE64_B64 = 86
	BYTE_SIZE128    = 128
	BYTE_SIZE1024   = 1024
	BYTE_SIZE64_HEX = 128
)

var CircuitList = map[string]CircuitInfo{
	// "compare-bytes-b64url": {
	// 	Circuit: &ccb.CircuitB64Url{
	// 		Bytes:    make([]uints.U8, BYTE_SIZE64),
	// 		BytesB64: make([]uints.U8, BYTE_SIZE64_B64),
	// 	},
	// 	Name:    "compare-bytes-b64url",
	// 	Version: 1,
	// },
	"compare-bytes": {
		Circuit: &ccb.CircuitBytes{
			Bytes:    make([]uints.U8, BYTE_SIZE64),
			PubBytes: make([]uints.U8, BYTE_SIZE64),
		},
		Name:        "compare-bytes",
		Version:     1,
		InputParser: &ccb.CircuitBytesInputParser{},
	},
	// "compare-bytes-cnf": {
	// 	Circuit: &ccb.CircuitCompareCnf{
	// 		HeaderB64:       make([]uints.U8, BYTE_SIZE128),
	// 		CnfB64:          make([]uints.U8, BYTE_SIZE1024),
	// 		PublicKeyDigest: make([]uints.U8, BYTE_SIZE32),
	// 	},
	// 	Name:    "compare-bytes-cnf",
	// 	Version: 1,
	// },
}
