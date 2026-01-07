// Package ecdsa implements GO interfaces to call ECDSA circuit implemented
// using longfellow-zk
package ecdsa

/*
#cgo darwin CFLAGS: -I../../cpp/include
#cgo darwin CXXFLAGS: -std=c++17
#cgo darwin LDFLAGS: -L${SRCDIR}/../../cpp/build -L/opt/homebrew/lib -llongfellow_wrapper -lcrypto -lzstd -lc++ -Wl,-rpath,${SRCDIR}/../../cpp/build
#include "ecdsa_c.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

// getLastError retrieves the last error from C++
func getLastError() string {
	cErr := C.ecdsa_get_last_error()
	return C.GoString(cErr)
}

// InitCircuit compiles and stores a circuit by name
// Call this once at startup for each circuit you need
// TODO: create a circuit registry
func InitCircuit(name string) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	if !C.ecdsa_init_circuit(cName) {
		return fmt.Errorf("failed to initialize circuit: %s", getLastError())
	}

	return nil
}

// FreeCircuit removes a circuit from storage
// Call this during shutdown or when you're done with a circuit
func FreeCircuit(name string) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	C.ecdsa_free_circuit(cName)
}

// Proof represents a serialized ZK proof
type Proof struct {
	data []byte
}

// Bytes returns the raw proof data
func (p *Proof) Bytes() []byte {
	return p.data
}

// Hex returns the proof as a hex string
func (p *Proof) Hex() string {
	return hex.EncodeToString(p.data)
}

// Size returns the size of the proof in bytes
func (p *Proof) Size() int {
	return len(p.data)
}

// ProofFromBytes creates a Proof from raw bytes
func ProofFromBytes(data []byte) *Proof {
	return &Proof{data: data}
}

// ProofFromHex creates a Proof from a hex string
func ProofFromHex(hexStr string) (*Proof, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return &Proof{data: data}, nil
}

// CreateProof creates an ECDSA ZK proof
func CreateProof(
	circuitName string,
	publicKeyX string,
	publicKeyY string,
	messageHash string,
	signatureR string,
	signatureS string,
) (*Proof, error) {

	cCircuit := C.CString(circuitName)
	cPubKeyX := C.CString(publicKeyX)
	cPubKeyY := C.CString(publicKeyY)
	cMsgHash := C.CString(messageHash)
	cSigR := C.CString(signatureR)
	cSigS := C.CString(signatureS)

	defer C.free(unsafe.Pointer(cCircuit))
	defer C.free(unsafe.Pointer(cPubKeyX))
	defer C.free(unsafe.Pointer(cPubKeyY))
	defer C.free(unsafe.Pointer(cMsgHash))
	defer C.free(unsafe.Pointer(cSigR))
	defer C.free(unsafe.Pointer(cSigS))

	var proofData unsafe.Pointer
	var proofSize C.size_t

	ok := C.ecdsa_create_proof(
		&proofData,
		&proofSize,
		cCircuit,
		cPubKeyX,
		cPubKeyY,
		cMsgHash,
		cSigR,
		cSigS,
	)

	if !ok {
		return nil, fmt.Errorf("failed to create proof: %s", getLastError())
	}

	proof := &Proof{
		data: C.GoBytes(proofData, C.int(proofSize)),
	}

	C.ecdsa_free_proof_data(proofData)
	return proof, nil
}

// VerifyProof verifies a ZK proof using a named circuit
// The circuit must have been previously initialized with InitCircuit()
func VerifyProof(
	circuitName string,
	publicKeyX string,
	publicKeyY string,
	messageHash string,
	proof *Proof,
) (bool, error) {
	if proof == nil || len(proof.data) == 0 {
		return false, fmt.Errorf("proof is nil or empty")
	}

	cCircuit := C.CString(circuitName)
	cPubKeyX := C.CString(publicKeyX)
	cPubKeyY := C.CString(publicKeyY)
	cMsgHash := C.CString(messageHash)

	defer C.free(unsafe.Pointer(cCircuit))
	defer C.free(unsafe.Pointer(cPubKeyX))
	defer C.free(unsafe.Pointer(cPubKeyY))
	defer C.free(unsafe.Pointer(cMsgHash))

	result := C.ecdsa_verify_proof(
		cCircuit,
		cPubKeyX,
		cPubKeyY,
		cMsgHash,
		unsafe.Pointer(&proof.data[0]),
		C.size_t(len(proof.data)),
	)

	if !result {
		errMsg := getLastError()
		if errMsg != "" {
			return false, fmt.Errorf("verification failed: %s", errMsg)
		}
		return false, nil // Verification failed, but no error
	}

	return true, nil
}
