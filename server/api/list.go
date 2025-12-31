package api

import (
	"github.com/mynextid/eudi-zk/circuits"
	assertcnf "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-cnf"
	assertecpubkeyd "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-ec-public-key-digest"
	assertisequal "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-is-equal"
	comparelex "github.com/mynextid/eudi-zk/circuits/compare-bytes/compare-lexicographically"
	decodeb64 "github.com/mynextid/eudi-zk/circuits/compare-bytes/decode-base64url"
	decodehex "github.com/mynextid/eudi-zk/circuits/compare-bytes/decode-hex"
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
	}

	for _, c := range circuitList {
		CircuitList[c.Name] = c

	}
}
