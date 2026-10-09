package store

import "github.com/cavi-ai/secure-agent/daemon/internal/model"

// SessionOutcomeHistory is retained history, never current action authority.
// Each source is read independently so an unavailable section does not erase
// the other receipts. Callers must establish that the session exists first.
type SessionOutcomeHistory struct {
	Reviews       []model.ReviewRecord        `json:"reviews"`
	Incidents     []model.IncidentReport      `json:"incidents"`
	Interventions []model.InterventionReceipt `json:"interventions"`
	Evidence      SessionOutcomeEvidence      `json:"evidence"`
}

type SessionOutcomeEvidence struct {
	Reviews       ReportSourceEvidence `json:"reviews"`
	Incidents     ReportSourceEvidence `json:"incidents"`
	Interventions ReportSourceEvidence `json:"interventions"`
}

func (s *Store) SessionOutcomes(id string) SessionOutcomeHistory {
	out := SessionOutcomeHistory{Reviews: []model.ReviewRecord{}, Incidents: []model.IncidentReport{}, Interventions: []model.InterventionReceipt{}}
	page, reviewErr := s.ListSessionFindingReviews(id)
	if reviewErr == nil && !page.Degraded {
		out.Reviews = page.Reviews
		for i := range out.Reviews {
			out.Reviews[i].AvailableScopes = nil
		}
	}
	out.Evidence.Reviews = ReportSourceEvidence{Available: reviewErr == nil && !page.Degraded, AtLimit: len(out.Reviews) >= 100, Limit: 100}
	interventions, interventionErr := s.RecentInterventions(id, 200)
	if interventionErr == nil {
		out.Interventions = interventions
	}
	out.Evidence.Interventions = ReportSourceEvidence{Available: interventionErr == nil, AtLimit: len(out.Interventions) >= 200, Limit: 200}
	incidents, incidentErr := s.SessionIncidents(id)
	if incidentErr == nil {
		out.Incidents = incidents
	}
	out.Evidence.Incidents = ReportSourceEvidence{Available: incidentErr == nil, AtLimit: len(out.Incidents) >= 100, Limit: 100}
	return out
}
