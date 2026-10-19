package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestBuildSessionFollowUpSelectsCanonicalItems(t *testing.T) {
	history := store.SessionOutcomeHistory{
		Reviews: []model.ReviewRecord{
			{ID: "newer", Revision: 4, Context: model.ReviewContext{Rule: "finding-rule"}, Decision: &model.ReviewDecisionReceipt{Revision: 3}, EvidenceFlagID: "flag-4", EvidenceFlagAvailable: true, EvidenceAvailable: true},
			{ID: "same", Revision: 3, Decision: &model.ReviewDecisionReceipt{Revision: 3}},
			{ID: "unreviewed", Revision: 4},
			{ID: "permission-review", Revision: 4, Context: model.ReviewContext{Rule: "permission-rule"}, Decision: &model.ReviewDecisionReceipt{Revision: 4, ScopeIDs: []string{"p2", "p1", "p2"}}},
			{ID: "invalid-revision", Revision: 4, Decision: &model.ReviewDecisionReceipt{Revision: 1 << 54, ScopeIDs: []string{"p3"}}},
			{ID: "too-many-scopes", Revision: 4, Decision: &model.ReviewDecisionReceipt{Revision: 4, ScopeIDs: make([]string, 129)}},
		},
		Guards: []store.GuardDecision{
			{ID: "session-guard", SessionID: "owned", RuleID: "guard-rule", Verdict: "allow", Scope: "session", ScopeIDs: []string{"g1", "g1"}},
			{ID: "foreign-guard", SessionID: "other", RuleID: "foreign", Verdict: "allow", Scope: "exact", ScopeIDs: []string{"g2"}},
			{ID: "deny-guard", SessionID: "owned", RuleID: "denied", Verdict: "deny", Scope: "session", ScopeIDs: []string{"g3"}},
			{ID: "broad-guard", SessionID: "owned", RuleID: "broad", Verdict: "allow", Scope: "always", ScopeIDs: []string{"g4"}},
		},
		Interventions: []model.InterventionReceipt{
			{ID: "requested", Kind: "pause", Status: "requested", Verification: "unknown", Limits: []string{"limit"}},
			{ID: "failed", Kind: "terminate", Status: "failed", Verification: "unknown"},
			{ID: "cancelled", Status: "cancelled"},
			{ID: "observed", Status: "applied", Verification: "observed"},
			{ID: "verified-family", Status: "applied", Verification: "verified", VerifiedBy: "captured-family-absent"},
			{ID: "verified-other", Status: "applied", Verification: "verified", VerifiedBy: "operator"},
		},
		Incidents: []model.IncidentReport{{ID: "incident", Remediation: &model.IncidentRemediation{Steps: []model.IncidentRemediationStep{
			{ID: "reported", Status: "reported", Verification: "not_verified", Item: model.RotateItem{Name: "Key", Action: "Rotate key"}, NewerEvidence: true},
			{ID: "pending", Status: "pending", Item: model.RotateItem{Name: "Other", Action: "Review"}},
		}}}},
		Evidence: store.SessionOutcomeEvidence{
			Guards: store.ReportSourceEvidence{Available: true, Limit: 200}, Reviews: store.ReportSourceEvidence{Available: true, Limit: 100},
			Incidents: store.ReportSourceEvidence{Available: true, Limit: 100}, Interventions: store.ReportSourceEvidence{Available: true, Limit: 200},
		},
	}

	follow := buildSessionFollowUp("owned", time.Now().UTC(), history)
	if follow.SchemaVersion != 1 || follow.SessionID != "owned" || follow.Partial {
		t.Fatalf("follow-up metadata = %+v", follow)
	}
	if len(follow.NewerEvidence) != 1 || follow.NewerEvidence[0].ID != "newer" || follow.NewerEvidence[0].Title != "finding-rule" || follow.NewerEvidence[0].DecisionRevision != 3 || !follow.NewerEvidence[0].EvidenceAvailable {
		t.Fatalf("newer evidence = %+v", follow.NewerEvidence)
	}
	if len(follow.ProcessActions) != 3 || follow.ProcessActions[0].ID != "requested" || follow.ProcessActions[1].ID != "failed" || follow.ProcessActions[2].ID != "verified-other" || len(follow.ProcessActions[0].Limits) != 1 {
		t.Fatalf("process actions = %+v", follow.ProcessActions)
	}
	if len(follow.ReportedActions) != 1 || follow.ReportedActions[0].IncidentID != "incident" || follow.ReportedActions[0].StepID != "reported" || !follow.ReportedActions[0].NewerEvidence || follow.ReportedActions[0].Verification != "not_verified" {
		t.Fatalf("reported actions = %+v", follow.ReportedActions)
	}
	if len(follow.Permissions) != 2 || follow.Permissions[0].IDs[0] != "p2" || len(follow.Permissions[0].IDs) != 2 || follow.Permissions[1].ID != "session-guard" || follow.Permissions[1].Status != "unknown" {
		t.Fatalf("permissions = %+v", follow.Permissions)
	}
}

func TestBuildSessionFollowUpPartialAndEmpty(t *testing.T) {
	allAvailable := store.SessionOutcomeEvidence{
		Guards: store.ReportSourceEvidence{Available: true, Limit: 200}, Reviews: store.ReportSourceEvidence{Available: true, Limit: 100},
		Incidents: store.ReportSourceEvidence{Available: true, Limit: 100}, Interventions: store.ReportSourceEvidence{Available: true, Limit: 200},
	}
	empty := store.SessionOutcomeHistory{Evidence: allAvailable}
	follow := buildSessionFollowUp("empty", time.Now().UTC(), empty)
	if follow.Partial || follow.NewerEvidence == nil || follow.ProcessActions == nil || follow.ReportedActions == nil || follow.Permissions == nil {
		t.Fatalf("complete empty follow-up = %+v", follow)
	}
	if len(follow.NewerEvidence)+len(follow.ProcessActions)+len(follow.ReportedActions)+len(follow.Permissions) != 0 {
		t.Fatalf("empty source produced follow-up items: %+v", follow)
	}

	partial := allAvailable
	partial.Guards.AtLimit = true
	partial.Interventions.Available = false
	follow = buildSessionFollowUp("partial", time.Now().UTC(), store.SessionOutcomeHistory{Evidence: partial})
	if !follow.Partial || follow.Sources.Guards.Available != true || !follow.Sources.Guards.AtLimit || follow.Sources.Interventions.Available {
		t.Fatalf("source limits/failures not represented: %+v", follow)
	}
}
