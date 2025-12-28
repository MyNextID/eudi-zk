package api

import (
	"github.com/mynextid/eudi-zk/circuits"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
)

// List of registered circuits
var CircuitList = map[string]*circuits.CircuitInfo{
	"compare-bytes": ccb.CBInfo,
}
