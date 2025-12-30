package circuits

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/mynextid/eudi-zk/zkcore"
)

// Circuit holds information about circuits
type Circuit struct {
	Instance *CircuitInstance
	Info     *CircuitInfo
}

// CircuitInstance with loaded constraint system and proving and public verifying keys
type CircuitInstance struct {
	CS           *constraint.ConstraintSystem
	ProvingKey   *groth16.ProvingKey
	VerifyingKey *groth16.VerifyingKey
	InputParser  InputParser
}

// CircuitID contains public circuit information
type CircuitID struct {
	ID           string `json:"id"`
	ProvingKey   string `json:"provingKey"`
	VerifyingKey string `json:"verifyingKey"`
}

// ID returns circuit fingerprint: H(circuit):H(proving-key):H(verifying-key) where H is hex encoded SHA256 hash of the payload
func (c Circuit) ID() (*CircuitID, error) {

	var csBuf bytes.Buffer
	_, err := (*c.Instance.CS).WriteTo(&csBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to write constrain system to buffer: %v", err)
	}
	csFp := fingerprintHex(csBuf.Bytes())

	var pkBuf bytes.Buffer
	_, err = (*c.Instance.ProvingKey).WriteTo(&pkBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to write proving key to buffer: %v", err)
	}
	pkB64 := base64.RawURLEncoding.EncodeToString(pkBuf.Bytes())
	pkFp := fingerprintHex(pkBuf.Bytes())

	var vkBuf bytes.Buffer
	_, err = (*c.Instance.VerifyingKey).WriteTo(&vkBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to write  key to buffer: %v", err)
	}
	vkB64 := base64.RawURLEncoding.EncodeToString(vkBuf.Bytes())
	vkFp := fingerprintHex(vkBuf.Bytes())

	fp := fmt.Sprintf("%s:%s:%s", csFp, pkFp, vkFp)

	return &CircuitID{
		ID:           fp,
		ProvingKey:   pkB64,
		VerifyingKey: vkB64,
	}, nil
}

func fingerprintHex(in []byte) string {
	digest := sha256.Sum256(in)
	return hex.EncodeToString(digest[:])
}

// Compile compiles and sets up a circuit from the CircuitInfo
func Compile(ci *CircuitInfo) (*Circuit, error) {

	cs, pk, vk, err := zkcore.Compile(&ci.Circuit)
	if err != nil {
		return nil, fmt.Errorf("circuit compilation failed: %v", err)
	}

	return &Circuit{
		Info: ci,
		Instance: &CircuitInstance{
			CS:           cs,
			ProvingKey:   pk,
			VerifyingKey: vk,
			InputParser:  ci.InputParser,
		},
	}, nil
}

// Parser returns the circuit instance parser
func (c CircuitInstance) Parser() InputParser {
	return c.InputParser
}

// // Public returns public circuit params
// func (c CircuitInstance) Public() PublicCircuitParams {
// 	return PublicCircuitParams{
// 		CS:           c.CS,
// 		InputParser:  c.InputParser,
// 		VerifyingKey: c.VerifyingKey,
// 	}
// }

// Prove function creates a ZK proof for the circuit instance and the input parameters
func (c CircuitInstance) Prove(assignment frontend.Circuit) ([]byte, error) {
	// Create witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %v", err)
	}

	// Generate proof
	proof, err := groth16.Prove(*c.CS, *c.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("proof creation failed: %v", err)
	}

	// proof to buffer
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("proof to buffer failed: %v", err)
	}
	return proofBuf.Bytes(), nil
}

// Prove function creates a ZK proof for the circuit instance and the input parameters
func (c Circuit) Prove(assignment frontend.Circuit) ([]byte, error) {
	return c.Instance.Prove(assignment)
}

// Verify verifies a proof for the given circuit and input params
func (c Circuit) Verify(assignment frontend.Circuit, proof []byte) error {

	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("witness creation failed: %v", err)
	}
	pw, err := w.Public()
	if err != nil {
		return fmt.Errorf("public witness creation failed: %v", err)
	}

	p := groth16.NewProof(ecc.BN254)
	_, err = p.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		return fmt.Errorf("failed to read the proof: %v", err)
	}

	err = groth16.Verify(p, *c.Instance.VerifyingKey, pw)
	if err != nil {
		return fmt.Errorf("proof verification failed: %v", err)
	}
	return nil
}

// ProveWithJSON generates a proof from JSON inputs
func (c Circuit) ProveWithJSON(publicInput, privateInput []byte) ([]byte, error) {

	assignment, err := c.Instance.InputParser.Parse(publicInput, privateInput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse inputs: %w", err)
	}

	return c.Prove(assignment)
}

// VerifyWithJSON verifies a proof using JSON public input
func (c Circuit) VerifyWithJSON(publicInput, proof []byte) error {

	// Parse only public input (pass empty private input)
	assignment, err := c.Instance.InputParser.Parse(publicInput, nil)
	if err != nil {
		return fmt.Errorf("failed to parse public input: %w", err)
	}

	return c.Verify(assignment, proof)
}

// ProveWithJSON generates a proof from JSON inputs
func (c *CircuitInstance) ProveWithJSON(publicInput, privateInput []byte) ([]byte, error) {

	assignment, err := c.InputParser.Parse(publicInput, privateInput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse inputs: %w", err)
	}

	return c.Prove(assignment)
}
