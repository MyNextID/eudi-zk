package api

import (
	"github.com/mynextid/eudi-zk/circuits"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
	assertcnf "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-cnf"
	assertisequal "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-is-equal"
)

// CircuitList holds all the registered circuits
var CircuitList = make(map[string]*circuits.CircuitInfo)

func init() {

	circuitList := []*circuits.CircuitInfo{
		assertisequal.Info,
		ccb.CBB64UrlInfo,
		assertcnf.Info}

	for _, c := range circuitList {
		CircuitList[c.Name] = c

	}
}
