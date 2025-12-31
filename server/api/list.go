package api

import (
	"github.com/mynextid/eudi-zk/circuits"
	assertcnf "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-cnf"
	assertecpubkey "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-ec-public-key"
	assertisequal "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-is-equal"
	decodeb64 "github.com/mynextid/eudi-zk/circuits/compare-bytes/decode-base64url"
)

// CircuitList holds all the registered circuits
var CircuitList = make(map[string]*circuits.CircuitInfo)

func init() {

	circuitList := []*circuits.CircuitInfo{
		assertisequal.Info,
		decodeb64.Info,
		assertcnf.Info,
		assertecpubkey.Info,
	}

	for _, c := range circuitList {
		CircuitList[c.Name] = c

	}
}
