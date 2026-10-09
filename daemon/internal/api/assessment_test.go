package api

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Decode the served contract rather than deriving expectations from the
// implementation: this also catches a projection omitted from the API.
func servedAssessment(t *testing.T, a *API, f model.Flag) map[string]any {
	t.Helper()
	b, err := json.Marshal(a.explainFlag(f, false))
	if err != nil {
		t.Fatal(err)
	}
	var ex map[string]any
	if err := json.Unmarshal(b, &ex); err != nil {
		t.Fatal(err)
	}
	assessment, ok := ex["assessment"].(map[string]any)
	if !ok {
		t.Fatal("explain omitted the independent finding assessment")
	}
	return assessment
}

func assessmentReadConnect() model.Flag {
	return model.Flag{ID: "read-connect", Rule: readConnectRule, Severity: 3, TS: time.Now(), Agent: "claude",
		Evidence: []model.EvidenceItem{
			{Kind: "read", Label: "/w/.env", Sub: "sensitive read", PID: 10, Chain: []int32{1}, TS: "2026-10-08T12:00:00Z"},
			{Kind: "connect", Label: "example.com:443", Sub: "egress", PID: 20, Chain: []int32{1}, TS: "2026-10-08T12:00:03Z"},
		}}
}

func TestAssessmentEvidencePrecedence(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	for _, tc := range []struct {
		name, risk, residual, basis string
		change                      func(*model.Flag)
	}{
		{"sibling timing cannot prove transmission", "review", "possible-exposure", "sibling-connect", func(f *model.Flag) {}},
		{"same reader then connection", "high", "possible-exposure", "same-tree-connect", func(f *model.Flag) { f.Evidence[1].PID = 10 }},
		{"model visible is distinct", "critical", "model-exposure", "model-visible-read", func(f *model.Flag) { f.Evidence[0].Sub = "agent tool read" }},
		{"older connection cannot be read then connect", "review", "possible-exposure", "os-read", func(f *model.Flag) { f.Evidence[1].PID = 10; f.Evidence[1].TS = "2026-10-08T11:59:59Z" }},
		{"legacy payload words are not payload proof", "unknown", "unknown", "legacy-text", func(f *model.Flag) { f.Evidence = model.EvidenceFromStrings("fingerprint payload matched; blocked") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := assessmentReadConnect()
			tc.change(&f)
			got := servedAssessment(t, a, f)
			if got["risk"] != tc.risk || got["residual_risk"] != tc.residual || got["control"] != "unknown" {
				t.Fatalf("assessment = %+v", got)
			}
			basis, _ := got["evidence_basis"].([]any)
			if !slices.Contains(basis, any(tc.basis)) {
				t.Fatalf("basis = %v, missing %s", basis, tc.basis)
			}
			for _, b := range basis {
				if b == "fingerprint-payload" || b == "pattern-payload" || b == "entropy-payload" {
					t.Fatalf("invented payload evidence: %v", basis)
				}
			}
			if len(got["limits"].([]any)) == 0 {
				t.Fatal("assessment omitted its evidence limits")
			}
		})
	}
}

func TestAcknowledgmentDoesNotChangeRisk(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	f := assessmentReadConnect()
	f.Evidence[0].Sub = "agent tool read"
	before := servedAssessment(t, a, f)
	f.Acknowledged = true
	after := servedAssessment(t, a, f)
	if before["review_state"] != "unreviewed" || after["review_state"] != "reviewed" {
		t.Fatalf("review states: %v / %v", before, after)
	}
	for _, key := range []string{"evidence_basis", "risk", "control", "residual_risk", "reason", "limits"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			t.Fatalf("acknowledgment changed %s: %v -> %v", key, before[key], after[key])
		}
	}
}

func TestAdvisorDoesNotOverrideDirectEvidence(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	f := assessmentReadConnect()
	f.Evidence[0].Sub = "agent tool read"
	f.Advisor = &model.AdvisorVerdict{Assessment: "benign", Confidence: .99, Rationale: "Routine traffic.", SuggestedAction: "allow-host"}
	got := servedAssessment(t, a, f)
	if got["risk"] != "critical" || got["residual_risk"] != "model-exposure" {
		t.Fatalf("advisor erased direct evidence: %v", got)
	}
	if got["advice"].(map[string]any)["assessment"] != "benign" {
		t.Fatal("advisor opinion must remain available separately")
	}
	if got["recommendation_id"] == "allow-host" {
		t.Fatal("conflicting opinion recommended a permission change")
	}
	a.store.PutFlag(f)
	a.store.PutAdvisorVerdict(f.ID, "flag", *f.Advisor)
	p := a.computePosture()
	if p.State != "critical" || len(p.Items) != 1 || p.Items[0].Severity != 3 {
		t.Fatalf("advisor downgraded posture: %+v", p)
	}
}

func TestReviewedExposureRemainsAvailableInHistory(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	f := assessmentReadConnect()
	f.Evidence[0].Sub = "agent tool read"
	a.store.PutFlag(f)
	mux := a.buildMux()
	ack := httptest.NewRecorder()
	mux.ServeHTTP(ack, httptest.NewRequest("POST", "/flags/acknowledge", strings.NewReader(`{"flag_id":"read-connect"}`)))
	if ack.Code != 200 {
		t.Fatalf("acknowledge: %d %s", ack.Code, ack.Body.String())
	}
	if p := a.computePosture(); p.NeedsYou != 0 {
		t.Fatalf("reviewed finding still demands a decision: %+v", p)
	}
	for _, path := range []string{"/flags/read-connect/explain", "/flags?limit=25"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 200 {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"review_state":"reviewed"`) || !strings.Contains(response.Body.String(), `"residual_risk":"model-exposure"`) {
			t.Fatalf("%s hid reviewed exposure: %s", path, response.Body.String())
		}
	}
}

func TestGroupedAssessmentPreservesStrongestReviewedEvidence(t *testing.T) {
	legacy := model.Flag{Severity: 3, Evidence: model.EvidenceFromStrings("secret sent")}
	direct := assessmentReadConnect()
	direct.Evidence[0].Sub = "agent tool read"
	direct.Acknowledged = true
	a := assessmentForFlags([]model.Flag{legacy, direct})
	if a.Risk != "critical" || a.ResidualRisk != "model-exposure" || a.ReviewState != "unreviewed" {
		t.Fatalf("group hid stronger reviewed evidence: %+v", a)
	}
	legacy.Acknowledged = true
	a = assessmentForFlags([]model.Flag{legacy, direct})
	if a.Risk != "critical" || a.ResidualRisk != "model-exposure" || a.ReviewState != "reviewed" {
		t.Fatalf("group review erased risk: %+v", a)
	}
}
