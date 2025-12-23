package ct_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/uints"
	ct "github.com/mynextid/eudi-zk/circuits/temporal"
	"github.com/mynextid/eudi-zk/common"
	"github.com/mynextid/eudi-zk/models"
)

// minimal over 18 test
func TestOver18(t *testing.T) {
	ccsPath := "compiled/ct-circuit-over18-v1.ccs"
	pkPath := "compiled/ct-proving-over18-v1.key"
	vkPath := "compiled/ct-verifying-over18-v1.key"

	forceCompile := true

	// == create test data ==
	// min date of birth value must be such that people born before that date are considered of age
	minDateOfBirth := "2004-01-01"
	data, err := MockOver18Data(minDateOfBirth)
	if err != nil {
		t.Fatalf("failed to generate data: %v", err)
	}

	// == create the circuit and execute it ==
	circuitTemplate := &ct.Over18{
		Payload:        make([]uints.U8, len(data.Payload)),
		DateB64:        make([]uints.U8, len(data.DateB64)),
		MinDateOfBirth: make([]uints.U8, len(data.MinDateOfBirth)),
	}

	// Create witness assignment with actual values
	assignment := &ct.Over18{
		Payload:         common.BytesToU8Array(data.Payload),
		DateB64:         common.BytesToU8Array(data.DateB64),
		DateB64Position: data.DateB64Position,
		DatePosition:    data.DatePosition,
		MinDateOfBirth:  common.StringToU8Array(data.MinDateOfBirth),
	}

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("[OK] Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuit(assignment, ccs, pk, vk)
}

type Over18Payload struct {
	Payload         []byte
	DateB64         []byte
	DateB64Position int
	DatePosition    int
	MinDateOfBirth  string
}

func MockOver18Data(minDateOfBirth string) (*Over18Payload, error) {
	// Generate ES256 (P-256) key pair
	// signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	panic(fmt.Sprintf("Failed to generate key: %v", err))
	// }

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	// pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.PublicKey.X, signerKey.PublicKey.Y)

	// pubKeyBytesDigest := sha256.Sum256(pubKeyBytes)
	// pubKeyBytesDigestHex := hex.EncodeToString(pubKeyBytesDigest[:])

	// Create JWS protected
	// protected := map[string]any{
	// 	"alg": "ES256",
	// 	"typ": "JOSE+JSON",
	// 	"cnf": map[string]string{
	// 		"kid": pubKeyBytesDigestHex,
	// 	},
	// }
	// protectedBytes, err := json.Marshal(protected)
	// if err != nil {
	// 	return nil, err
	// }
	// protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)

	payload := models.GetDemoPID()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	fmt.Println("payloadB64", payloadB64)

	// signature := fmt.Sprintf("%s.%s", protectedB64, payloadB64)

	// digest := sha256.Sum256([]byte(signature))

	// Sign the digest of the challenge
	// r, s, err := ecdsa.Sign(rand.Reader, signerKey, digest[:])
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to sign the credential %v", err)
	// }

	// == find the position of the elements ==
	payloadMap, err := StructToMap(payload)
	dateIndexStart, dateIndexEnd, err := GetClaimRange(payloadMap, payloadBytes, "birthdate")
	birthdateB64 := GetClaimB64(payloadBytes, dateIndexStart, dateIndexEnd, "birthdate")

	fmt.Println("birthdateB64", birthdateB64)
	bd, _ := base64.URLEncoding.DecodeString(birthdateB64)
	fmt.Println("birthdate decoded", string(bd))

	b64Index := strings.Index(payloadB64, birthdateB64)
	if b64Index == -1 {
		return nil, fmt.Errorf("failed to get b64Index index")
	}

	birthdate, err := base64.RawURLEncoding.DecodeString(birthdateB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode birthdate")
	}

	dateIndex := strings.Index(string(birthdate), payloadMap["birthdate"].(string))
	if dateIndex == -1 {
		return nil, fmt.Errorf("failed to get date index")
	}

	return &Over18Payload{
		Payload:         []byte(payloadB64),
		DateB64:         []byte(birthdateB64),
		DateB64Position: b64Index,
		DatePosition:    dateIndex,
		MinDateOfBirth:  minDateOfBirth,
	}, nil
}

func GetClaimRange(obj map[string]any, objJSON []byte, claim string) (start, end int, err error) {

	element := map[string]any{
		claim: obj[claim],
	}
	elementBytes, err := json.Marshal(element)
	if err != nil {
		return 0, 0, err
	}
	elementString := string(elementBytes)
	elementString = strings.TrimPrefix(elementString, "{")
	elementString = strings.TrimSuffix(elementString, "}")

	// Find where the claim appears
	indexStart := strings.Index(string(objJSON), elementString)
	if indexStart == -1 {
		return 0, 0, fmt.Errorf("element not found in JSON")
	}
	fmt.Println(elementString)
	// Length of the cnf variable
	indexEnd := indexStart + len(elementString)

	start, end = common.B64Align(indexStart, indexEnd)
	fmt.Println(indexStart, indexEnd)
	fmt.Println(start, end)
	return start, end, nil
}

func GetClaimB64(objJSON []byte, indexStart, indexEnd int, claim string) string {
	data := objJSON[indexStart:indexEnd]

	return base64.RawURLEncoding.EncodeToString(data)
}

func StructToMap(input any) (map[string]any, error) {
	var result map[string]any
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(inputBytes, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
