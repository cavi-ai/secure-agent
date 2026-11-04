package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestRoutineUntrustedIncidentStaysInHistory(t *testing.T) {
	for _, tc := range []struct {
		name          string
		decision      string
		injected      bool
		missingFlag   bool
		credential    bool
		aggregated    bool
		wantAttention bool
	}{
		{name: "allowed send", decision: "allowed"},
		{name: "monitored send", decision: "monitored"},
		{name: "matched injection", decision: "monitored", injected: true, wantAttention: true},
		{name: "missing evidence", missingFlag: true, wantAttention: true},
		{name: "credential evidence", decision: "allowed", credential: true, wantAttention: true},
		{name: "additional evidence", decision: "allowed", aggregated: true, wantAttention: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := attentionAPI(t, nil)
			at := time.Now()
			f := untrustedEgressFlag(at, tc.decision)
			if tc.injected {
				f.Evidence = append(f.Evidence, model.EvidenceItem{Kind: "untrusted-input", Rule: "injection", Label: "matched instructions"})
			}
			if !tc.missingFlag {
				if _, err := a.store.PutFlag(f); err != nil {
					t.Fatal(err)
				}
			}
			// Existing reports can carry the older, inflated risk. Reading the
			// attention queue must not rewrite that historical report.
			inc := model.IncidentReport{ID: "tool-send-incident", FlagID: f.ID, Rule: f.Rule,
				Risk: model.RiskHigh, Timestamp: at, Agent: f.Agent, SessionID: f.SessionID}
			if tc.credential {
				inc.RotateList = []model.RotateItem{{Category: model.CategoryCloudCreds, Risk: model.RiskCritical}}
			}
			if tc.aggregated {
				inc.AggregateCount = 2
			}
			if err := a.store.PutIncident(inc); err != nil {
				t.Fatal(err)
			}
			p := a.computePosture()
			queued := false
			for _, it := range p.Items {
				queued = queued || it.Kind == "incident" && it.ID == inc.ID
			}
			if queued != tc.wantAttention || !tc.wantAttention && p.NeedsYou != 0 {
				t.Fatalf("incident queued = %v, needs_you = %d, want queued = %v", queued, p.NeedsYou, tc.wantAttention)
			}
			stored, err := a.store.GetIncident(inc.ID)
			if err != nil || stored == nil || stored.Risk != model.RiskHigh {
				t.Fatalf("historical report changed: %+v, %v", stored, err)
			}
		})
	}
}
