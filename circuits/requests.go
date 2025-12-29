package circuits

import (
	"encoding/json"
	"fmt"

	"github.com/mynextid/eudi-zk/zkcore"
)

// Request is an interface to store example requests
type Request struct {
	Public  any `json:"public"`
	Private any `json:"private,omitempty"`
	Proof   any `json:"proof,omitempty"`
}

// Save saves a request
func (r Request) Save(name string) error {

	bytes, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal the request: %v", err)
	}
	return zkcore.SecureWriteFile(name, bytes, 0640)
}

// LoadRequest loads a request
func LoadRequest(name string) (*Request, error) {
	bytes, err := zkcore.SecureReadFile(name)
	if err != nil {
		return nil, err
	}

	var r Request
	err = json.Unmarshal(bytes, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}
