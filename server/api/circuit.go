package api

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// Circuit with loaded constraint system and proving and public verifying keys
type Circuit struct {
	CS           constraint.ConstraintSystem
	ProvingKey   groth16.ProvingKey
	VerifyingKey groth16.VerifyingKey
	InputParser  InputParser
}

// InputParser converts raw input to circuit assignment
type InputParser interface {
	Parse(publicInput, privateInput []byte) (frontend.Circuit, error)
}

// PublicCircuit with the constraint system and public verifying keys
type PublicCircuit struct {
	CS           constraint.ConstraintSystem
	VerifyingKey groth16.VerifyingKey
	InputParser  InputParser
}

func (c Circuit) Public() PublicCircuit {
	return PublicCircuit{
		CS:           c.CS,
		InputParser:  c.InputParser,
		VerifyingKey: c.VerifyingKey,
	}
}

func (c Circuit) Prove(assignment frontend.Circuit) ([]byte, error) {
	// Create witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %v", err)
	}

	// Generate proof
	proof, err := groth16.Prove(c.CS, c.ProvingKey, witness)
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

// Verify verifies a proof
func (c PublicCircuit) Verify(assignment frontend.Circuit, proof groth16.Proof) error {

	pw, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("witness creation failed: %v", err)
	}

	err = groth16.Verify(proof, c.VerifyingKey, pw)
	if err != nil {
		return fmt.Errorf("proof verification failed: %v", err)
	}
	return nil
}

// ProveWithJSON generates a proof from JSON inputs
func (c *Circuit) ProveWithJSON(circuitName string, publicInput, privateInput []byte) ([]byte, error) {

	assignment, err := c.InputParser.Parse(publicInput, privateInput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse inputs: %w", err)
	}

	return c.Prove(assignment)
}

// VerifyWithJSON verifies a proof using JSON public input
func (c PublicCircuit) VerifyWithJSON(circuitName string, publicInput, proofBytes []byte) error {

	// Parse only public input (pass empty private input)
	assignment, err := c.InputParser.Parse(publicInput, []byte("{}"))
	if err != nil {
		return fmt.Errorf("failed to parse public input: %w", err)
	}

	proof := groth16.NewProof(ecc.BN254)
	buf := bytes.NewReader(proofBytes)
	_, err = proof.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("failed to parse the proof: %w", err)
	}

	return c.Verify(assignment, proof)
}
