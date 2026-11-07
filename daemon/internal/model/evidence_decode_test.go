package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestLegacyEvidenceClearsStructuredMetadata(t *testing.T) {
	e := EvidenceItem{Kind: "read", PID: 42, Exe: "/bin/tool", Chain: []int32{1, 42}, Owners: []string{"owner"}, Payload: &PayloadEvidence{}}
	if err := json.Unmarshal([]byte(`"legacy"`), &e); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e, EvidenceItem{Kind: "text", Label: "legacy", Text: "legacy"}) {
		t.Fatalf("legacy text retained structured evidence: %#v", e)
	}
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
}
