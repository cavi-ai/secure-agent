package api

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func payloadFlag(t *testing.T, layer, findingAction, requestAction string) model.Flag {
	t.Helper()
	var f model.Flag
	err := json.Unmarshal([]byte(fmt.Sprintf(`{"id":"payload","rule":"proxy-secret-leak","severity":3,"evidence":[{"kind":"violation","sub":"payload inspection","label":"fixture-rule","payload":{"layer":%q,"field":"body","verdict":"leak","finding_action":%q,"request_action":%q}}]}`, layer, findingAction, requestAction)), &f)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPayloadAssessmentUsesRequestGateNotRuleMode(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, nil)
	for _, tc := range []struct{ layer, finding, request, control string }{
		{"fingerprint", "block", "block", "blocked"},
		{"pattern", "would-block", "would-block", "observed-only"},
		// A monitor-only match can share a request another rule blocked.
		{"fingerprint", "would-block", "block", "blocked"},
	} {
		f := payloadFlag(t, tc.layer, tc.finding, tc.request)
		got := servedAssessment(t, a, f)
		if got["control"] != tc.control || got["risk"] != "critical" || got["residual_risk"] != "transmission-attempt" {
			t.Fatalf("%+v: assessment = %+v", tc, got)
		}
		if !slices.Contains(got["evidence_basis"].([]any), any(tc.layer+"-payload")) {
			t.Fatalf("missing typed match: %+v", got)
		}
		f.Acknowledged = true
		if reviewed := servedAssessment(t, a, f); reviewed["control"] != tc.control || reviewed["residual_risk"] != "transmission-attempt" {
			t.Fatalf("review erased outcome: %+v", reviewed)
		}
		md := renderSessionMarkdown(store.SessionReport{Flags: []model.Flag{f}})
		if !strings.Contains(md, "control: "+tc.control) || !strings.Contains(md, "transmission-attempt") || !strings.Contains(md, "reviewed") {
			t.Fatalf("export omitted outcome: %s", md)
		}
	}
}

func TestPayloadAssessmentRejectsUnsupportedProof(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, nil)
	for _, tc := range []struct{ layer, finding, request string }{
		{"entropy", "block", "block"},
		{"pattern", "block", "would-block"},
		{"pattern", "allow", "block"},
		{"pattern", "block", ""},
		{"future-layer", "block", "block"},
	} {
		if got := servedAssessment(t, a, payloadFlag(t, tc.layer, tc.finding, tc.request)); got["control"] != "unknown" || got["risk"] != "unknown" {
			t.Fatalf("invalid proof credited: %+v -> %+v", tc, got)
		}
	}
	f := model.Flag{Rule: "proxy-secret-leak", Evidence: model.EvidenceFromStrings("fingerprint payload matched; blocked")}
	if got := servedAssessment(t, a, f); got["control"] != "unknown" {
		t.Fatalf("legacy prose credited: %+v", got)
	}
}
