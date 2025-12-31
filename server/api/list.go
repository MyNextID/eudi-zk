package api

import (
	"github.com/mynextid/eudi-zk/circuits"
	assertcnf "github.com/mynextid/eudi-zk/circuits/basic-circuits/assert-cnf"
	assertecpubkeyd "github.com/mynextid/eudi-zk/circuits/basic-circuits/assert-ec-public-key-digest"
	assertisequal "github.com/mynextid/eudi-zk/circuits/basic-circuits/assert-is-equal"
	assertissubset "github.com/mynextid/eudi-zk/circuits/basic-circuits/assert-is-subset"
	comparelex "github.com/mynextid/eudi-zk/circuits/basic-circuits/compare-lexicographically"
	decodeb64 "github.com/mynextid/eudi-zk/circuits/basic-circuits/decode-base64url"
	decodehex "github.com/mynextid/eudi-zk/circuits/basic-circuits/decode-hex"
)

// CircuitList holds all the registered circuits
var CircuitList = make(map[string]*circuits.CircuitInfo)

func init() {

	circuitList := []*circuits.CircuitInfo{
		assertisequal.Info,
		decodeb64.Info,
		decodehex.Info,
		assertcnf.Info,
		assertecpubkeyd.Info,
		comparelex.Info,
		assertissubset.Info,
	}

	for _, c := range circuitList {
		CircuitList[c.Name] = c

	}
}
