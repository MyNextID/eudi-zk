package api

import (
	"github.com/mynextid/eudi-zk/circuits"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
	assertcnf "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-cnf"
)

// CircuitList holds all the registered circuits
var CircuitList = make(map[string]*circuits.CircuitInfo)

func init() {

	circuitList := []*circuits.CircuitInfo{
		ccb.CBInfo,
		ccb.CBB64UrlInfo,
		assertcnf.CompareCnfInfo}

	for _, c := range circuitList {
		CircuitList[c.Name] = c

	}
}
