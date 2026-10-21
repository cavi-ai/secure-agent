package store

import (
	"context"
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// SessionOutcomeHistory is retained history, never current action authority.
// Each source is read independently so an unavailable section does not erase
// the other receipts. SessionOutcomes does not check identity; report
// aggregation calls it after its own identity read. Request handlers use
// SessionOutcome.
type SessionOutcomeHistory struct {
	Guards        []GuardDecision             `json:"guards"`
	Reviews       []model.ReviewRecord        `json:"reviews"`
	Incidents     []model.IncidentReport      `json:"incidents"`
	Interventions []model.InterventionReceipt `json:"interventions"`
	Evidence      SessionOutcomeEvidence      `json:"evidence"`
}

type SessionOutcomeEvidence struct {
	Guards        ReportSourceEvidence `json:"guards"`
	Reviews       ReportSourceEvidence `json:"reviews"`
	Incidents     ReportSourceEvidence `json:"incidents"`
	Interventions ReportSourceEvidence `json:"interventions"`
}

type sessionOutcomeReader interface {
	GuardDecisionHistory(string, int) ([]GuardDecision, error)
	ListSessionFindingReviews(string) (ReviewPage, error)
	RecentInterventions(string, int) ([]model.InterventionReceipt, error)
	SessionIncidents(string) ([]model.IncidentReport, error)
}

func (s *Store) SessionOutcomes(id string) SessionOutcomeHistory {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	history, _ := s.sessionOutcomesContext(ctx, id)
	return history
}

func emptySessionOutcomes() SessionOutcomeHistory {
	return SessionOutcomeHistory{Guards: []GuardDecision{}, Reviews: []model.ReviewRecord{}, Incidents: []model.IncidentReport{}, Interventions: []model.InterventionReceipt{}, Evidence: SessionOutcomeEvidence{
		Guards: ReportSourceEvidence{Limit: 200}, Reviews: ReportSourceEvidence{Limit: 100}, Incidents: ReportSourceEvidence{Limit: 100}, Interventions: ReportSourceEvidence{Limit: 200},
	}}
}

// readSessionOutcomeHistory retains readable receipt sources independently.
// The returned review rows do not carry authority to create a new scope.
func readSessionOutcomeHistory(reader sessionOutcomeReader, id string) SessionOutcomeHistory {
	out := emptySessionOutcomes()
	guards, guardErr := reader.GuardDecisionHistory(id, 200)
	if guardErr == nil {
		out.Guards = guards
	}
	out.Evidence.Guards = ReportSourceEvidence{Available: guardErr == nil, AtLimit: len(out.Guards) >= 200, Limit: 200}
	page, reviewErr := reader.ListSessionFindingReviews(id)
	if reviewErr == nil && !page.Degraded {
		out.Reviews = slices.Clone(page.Reviews)
		for i := range out.Reviews {
			out.Reviews[i].AvailableScopes = nil
		}
	}
	out.Evidence.Reviews = ReportSourceEvidence{Available: reviewErr == nil && !page.Degraded, AtLimit: len(out.Reviews) >= 100, Limit: 100}
	interventions, interventionErr := reader.RecentInterventions(id, 200)
	if interventionErr == nil {
		out.Interventions = interventions
	}
	out.Evidence.Interventions = ReportSourceEvidence{Available: interventionErr == nil, AtLimit: len(out.Interventions) >= 200, Limit: 200}
	incidents, incidentErr := reader.SessionIncidents(id)
	if incidentErr == nil {
		out.Incidents = incidents
	}
	out.Evidence.Incidents = ReportSourceEvidence{Available: incidentErr == nil, AtLimit: len(out.Incidents) >= 100, Limit: 100}
	return out
}
