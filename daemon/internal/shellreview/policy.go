package shellreview

import (
	_ "embed"
	"encoding/json"
)

// The offline customization tool uses this same versioned policy. Go's JSON
// encoder sorts criteria keys; tuning must preserve that serving order.
//
//go:embed policy.json
var policyJSON []byte

type classificationPolicy struct {
	Version      string            `json:"version"`
	Criteria     map[string]string `json:"criteria"`
	Instructions string            `json:"instructions"`
}

var policy = func() classificationPolicy {
	var p classificationPolicy
	if err := json.Unmarshal(policyJSON, &p); err != nil {
		panic("invalid embedded shell classification policy")
	}
	return p
}()

var policyVersion = policy.Version
var criteria = policy.Criteria
