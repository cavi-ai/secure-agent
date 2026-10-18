package api

import (
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

const sessionFollowUpSchemaVersion = 1

type SessionFollowUp struct {
	SchemaVersion   int                          `json:"schema_version"`
	SessionID       string                       `json:"session_id"`
	ObservedAt      time.Time                    `json:"observed_at"`
	Partial         bool                         `json:"partial"`
	Sources         store.SessionOutcomeEvidence `json:"sources"`
	NewerEvidence   []SessionFollowUpEvidence    `json:"newer_evidence"`
	ProcessActions  []SessionProcessAction       `json:"process_actions"`
	ReportedActions []SessionReportedAction      `json:"reported_actions"`
	Permissions     []SessionPermissionLink      `json:"permissions"`
}

type SessionFollowUpEvidence struct {
	ID                string `json:"id"`
	Title             string `json:"title"`
	Revision          int64  `json:"revision"`
	DecisionRevision  int64  `json:"decision_revision"`
	EvidenceFlagID    string `json:"evidence_flag_id"`
	EvidenceAvailable bool   `json:"evidence_available"`
}

type SessionProcessAction struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Status       string   `json:"status"`
	Verification string   `json:"verification"`
	VerifiedBy   string   `json:"verified_by"`
	Limits       []string `json:"limits"`
}

type SessionReportedAction struct {
	IncidentID    string `json:"incident_id"`
	StepID        string `json:"step_id"`
	Title         string `json:"title"`
	Action        string `json:"action"`
	NewerEvidence bool   `json:"newer_evidence"`
	Verification  string `json:"verification"`
}

type SessionPermissionLink struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	IDs    []string `json:"ids"`
	Title  string   `json:"title"`
	Status string   `json:"status"`
}

func buildSessionFollowUp(sessionID string, observedAt time.Time, history store.SessionOutcomeHistory) SessionFollowUp {
	follow := SessionFollowUp{
		SchemaVersion:   sessionFollowUpSchemaVersion,
		SessionID:       sessionID,
		ObservedAt:      observedAt,
		Sources:         history.Evidence,
		NewerEvidence:   []SessionFollowUpEvidence{},
		ProcessActions:  []SessionProcessAction{},
		ReportedActions: []SessionReportedAction{},
		Permissions:     []SessionPermissionLink{},
	}
	for _, source := range []store.ReportSourceEvidence{history.Evidence.Guards, history.Evidence.Reviews, history.Evidence.Incidents, history.Evidence.Interventions} {
		if !source.Available || source.AtLimit {
			follow.Partial = true
		}
	}

	for _, review := range history.Reviews {
		if review.Decision != nil && review.Revision > review.Decision.Revision {
			title := review.Context.Rule
			if title == "" {
				title = "Finding review"
			}
			follow.NewerEvidence = append(follow.NewerEvidence, SessionFollowUpEvidence{
				ID: review.ID, Title: title, Revision: review.Revision, DecisionRevision: review.Decision.Revision,
				EvidenceFlagID:    review.EvidenceFlagID,
				EvidenceAvailable: review.EvidenceAvailable && review.EvidenceFlagAvailable && review.EvidenceFlagID != "",
			})
		}
		if review.Decision != nil && safePositiveRevision(review.Decision.Revision) && validSessionScopeIDs(review.Decision.ScopeIDs) {
			title := review.Context.Rule
			if title == "" {
				title = "Review decision"
			}
			follow.Permissions = append(follow.Permissions, SessionPermissionLink{
				ID: review.ID, Kind: "review", IDs: dedupeSessionScopeIDs(review.Decision.ScopeIDs), Title: title, Status: "unknown",
			})
		}
	}
	for _, receipt := range history.Interventions {
		if receipt.Status == "cancelled" || (receipt.Status == "applied" && (receipt.Verification == "observed" || (receipt.Verification == "verified" && receipt.VerifiedBy == "captured-family-absent"))) {
			continue
		}
		limits := slices.Clone(receipt.Limits)
		if limits == nil {
			limits = []string{}
		}
		follow.ProcessActions = append(follow.ProcessActions, SessionProcessAction{
			ID: receipt.ID, Kind: receipt.Kind, Status: receipt.Status, Verification: receipt.Verification,
			VerifiedBy: receipt.VerifiedBy, Limits: limits,
		})
	}
	for _, incident := range history.Incidents {
		if incident.Remediation == nil {
			continue
		}
		for _, step := range incident.Remediation.Steps {
			if step.Status != "reported" {
				continue
			}
			title := step.Item.Name
			if title == "" {
				title = step.Item.Action
			}
			follow.ReportedActions = append(follow.ReportedActions, SessionReportedAction{
				IncidentID: incident.ID, StepID: step.ID, Title: title, Action: step.Item.Action,
				NewerEvidence: step.NewerEvidence, Verification: "not_verified",
			})
		}
	}
	for _, decision := range history.Guards {
		if decision.SessionID != sessionID || decision.Verdict != "allow" || (decision.Scope != "session" && decision.Scope != "exact") || !validSessionScopeIDs(decision.ScopeIDs) {
			continue
		}
		follow.Permissions = append(follow.Permissions, SessionPermissionLink{
			ID: decision.ID, Kind: "guard", IDs: dedupeSessionScopeIDs(decision.ScopeIDs), Title: decision.RuleID, Status: "unknown",
		})
	}
	return follow
}

func safePositiveRevision(revision int64) bool {
	const maxSafeInteger = int64(1<<53 - 1)
	return revision > 0 && revision <= maxSafeInteger
}

func validSessionScopeIDs(ids []string) bool {
	if len(ids) == 0 || len(ids) > 128 {
		return false
	}
	for _, id := range ids {
		if id == "" {
			return false
		}
	}
	return true
}

func dedupeSessionScopeIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
