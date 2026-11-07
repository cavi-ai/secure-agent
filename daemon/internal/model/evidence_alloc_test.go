//go:build !race

package model

import (
	"encoding/json"
	"testing"
)

// Race instrumentation randomly discards encoding/json's pooled scanners.
// Compare allocations without instrumentation; decoding is tested with both.
type objectEvidence EvidenceItem

func (o *objectEvidence) UnmarshalJSON(data []byte) error {
	type alias EvidenceItem
	return json.Unmarshal(data, (*alias)(o))
}

func TestEvidenceItemObjectDecodeAllocations(t *testing.T) {
	obj := []byte(`{"kind":"read","label":"/work/credentials","sub":"sensitive read","pid":42}`)
	reference := testing.AllocsPerRun(200, func() {
		var o objectEvidence
		_ = json.Unmarshal(obj, &o)
	})
	viaMethod := testing.AllocsPerRun(200, func() {
		var e EvidenceItem
		_ = json.Unmarshal(obj, &e)
	})
	if viaMethod > reference {
		t.Fatalf("EvidenceItem decode allocates %.0f times, an object-only decode %.0f", viaMethod, reference)
	}
}
