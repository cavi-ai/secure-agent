package model

import (
	"encoding/json"
	"testing"
)

// objectEvidence decodes the object form only: the cost EvidenceItem's
// decoder must match for an object.
type objectEvidence EvidenceItem

func (o *objectEvidence) UnmarshalJSON(data []byte) error {
	type alias EvidenceItem
	return json.Unmarshal(data, (*alias)(o))
}

// An object evidence item decodes without a failed string attempt first, and
// the legacy bare-string form still decodes as text.
func TestEvidenceItemDecodesEachFormDirectly(t *testing.T) {
	obj := []byte(`{"kind":"read","label":"/work/credentials","sub":"sensitive read","pid":42}`)
	var e EvidenceItem
	if err := json.Unmarshal(obj, &e); err != nil || e.Kind != "read" || e.Label != "/work/credentials" || e.PID != 42 {
		t.Fatalf("object = %+v, %v", e, err)
	}
	var legacy EvidenceItem
	if err := json.Unmarshal([]byte(` "read ~/.aws/credentials"`), &legacy); err != nil || legacy.Kind != "text" || legacy.Text != "read ~/.aws/credentials" {
		t.Fatalf("legacy = %+v, %v", legacy, err)
	}
	if err := json.Unmarshal([]byte(`42`), &legacy); err == nil {
		t.Fatal("a number decoded as evidence")
	}

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
