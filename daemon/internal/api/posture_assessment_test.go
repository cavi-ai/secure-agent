package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestPosturePreservesFindingAssessment(t *testing.T) {
	read := assessmentReadConnect()
	read.Evidence[0].Sub = "agent tool read"
	for _, tc := range []struct {
		name, risk, control, residual, reason string
		flag                                  model.Flag
	}{
		{"unknown", "unknown", "unknown", "unknown", "The detector reported this finding; its evidence does not establish exposure or a control outcome.", model.Flag{ID: "unknown", Rule: "proxy-secret-leak", Severity: 3, Evidence: model.EvidenceFromStrings("blocked")}},
		{"model visible", "critical", "unknown", "model-exposure", "A sensitive file was read through an agent tool and became model-visible.", read},
		{"monitor", "critical", "observed-only", "transmission-attempt", "A registered secret fingerprint matched an inspected outbound request body. The local proxy observed this attempt without blocking it.", payloadFlag(t, "fingerprint", "would-block", "would-block")},
		{"blocked", "critical", "blocked", "transmission-attempt", "A registered secret fingerprint matched an inspected outbound request body. The local proxy rejected this request before forwarding.", payloadFlag(t, "fingerprint", "block", "block")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := derivePosture(postureInputs{Status: Status{Running: true}, Generated: time.Now(), Flags: []model.Flag{tc.flag}})
			if p.State != "critical" || p.NeedsYou != 1 || p.Items[0].Severity != 3 {
				t.Fatalf("priority changed: %+v", p)
			}
			if p.Summary != tc.reason {
				t.Fatalf("summary = %q, want evidence-qualified %q", p.Summary, tc.reason)
			}
			if tc.risk == "unknown" && p.Items[0].Title != "Finding needs evidence review" {
				t.Fatalf("unknown evidence has a conclusive title: %q", p.Items[0].Title)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Items []struct {
					Assessment model.FindingAssessment `json:"assessment"`
				} `json:"items"`
			}
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			a := wire.Items[0].Assessment
			if a.Risk != tc.risk || a.Control != tc.control || a.ResidualRisk != tc.residual || len(a.Limits) == 0 {
				t.Fatalf("headline omitted or changed assessment: %+v", a)
			}
			group := p.Groups[0].Items[0].Assessment
			if group == nil || !reflect.DeepEqual(a.EvidenceBasis, group.EvidenceBasis) || a.Reason != group.Reason || !reflect.DeepEqual(a.Limits, group.Limits) {
				t.Fatalf("headline and decision evidence disagree: %+v / %+v", a, group)
			}
		})
	}
}

func TestPostureReviewKeepsEvidenceAndReviewBoundary(t *testing.T) {
	f := assessmentReadConnect()
	f.Evidence[0].Sub = "agent tool read"
	a := model.AssessFinding(f)
	r := model.ReviewRecord{ID: "review", Severity: 3, EvidenceAvailable: true, Assessment: a,
		Context: model.ReviewContext{Rule: f.Rule, SessionID: "session", Attribution: "stored-session"}}
	p := derivePosture(postureInputs{Status: Status{Running: true}, Generated: time.Now(), Reviews: []model.ReviewRecord{r}})
	if p.NeedsYou != 1 || p.Items[0].Kind != "review" || p.Summary != "A sensitive file was read through an agent tool and became model-visible." {
		t.Fatalf("review headline: %+v", p)
	}
	// Reviewed records are excluded at the storage boundary; an acknowledged
	// source also leaves the queue without changing its retained assessment.
	st := testStore(t)
	st.PutFlag(f)
	st.AcknowledgeFlag(f.ID)
	p = newTestAPI(Deps{SocketPath: "", Store: st, Killer: nil, Status: func() Status { return Status{Running: true} }}).computePosture()
	if p.NeedsYou != 0 || p.State != "all-clear" || !strings.Contains(p.Summary, "remaining risk") {
		t.Fatalf("review erased risk or retained a pending decision: %+v", p)
	}
}
