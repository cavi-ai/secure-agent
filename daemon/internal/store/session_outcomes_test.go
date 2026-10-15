package store

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type memoryOutcomeReader struct {
	reviews           ReviewPage
	reviewErr         error
	incidents         []model.IncidentReport
	incidentErr       error
	interventions     []model.InterventionReceipt
	interventionErr   error
	sessions          map[string]string
	interventionLimit int
}

func (s *memoryOutcomeReader) GuardDecisionHistory(string, int) ([]GuardDecision, error) {
	return []GuardDecision{}, nil
}

func (s *memoryOutcomeReader) ListSessionFindingReviews(id string) (ReviewPage, error) {
	s.sessions["reviews"] = id
	return s.reviews, s.reviewErr
}

func (s *memoryOutcomeReader) RecentInterventions(id string, limit int) ([]model.InterventionReceipt, error) {
	s.sessions["interventions"], s.interventionLimit = id, limit
	return s.interventions, s.interventionErr
}

func (s *memoryOutcomeReader) SessionIncidents(id string) ([]model.IncidentReport, error) {
	s.sessions["incidents"] = id
	return s.incidents, s.incidentErr
}

func TestOutcomeHistoryIndependentFailuresAndRecovery(t *testing.T) {
	failed := errors.New("receipt source unavailable")
	for _, source := range []string{"reviews", "degraded reviews", "incidents", "interventions", "all"} {
		t.Run(source, func(t *testing.T) {
			s := &memoryOutcomeReader{
				reviews:       ReviewPage{Reviews: []model.ReviewRecord{{ID: "review"}}},
				incidents:     []model.IncidentReport{{ID: "incident"}},
				interventions: []model.InterventionReceipt{{ID: "control", Status: "failed", Verification: "unknown"}},
				sessions:      map[string]string{},
			}
			badReviews := source == "reviews" || source == "degraded reviews" || source == "all"
			badIncidents := source == "incidents" || source == "all"
			badInterventions := source == "interventions" || source == "all"
			if badReviews {
				if source == "degraded reviews" {
					s.reviews.Degraded = true
				} else {
					s.reviewErr = failed
				}
			}
			if badIncidents {
				s.incidentErr = failed
			}
			if badInterventions {
				s.interventionErr = failed
			}
			out := readSessionOutcomeHistory(s, "owned")
			if out.Evidence.Reviews.Available == badReviews || out.Evidence.Incidents.Available == badIncidents || out.Evidence.Interventions.Available == badInterventions {
				t.Fatalf("source availability misreported: %+v", out.Evidence)
			}
			if len(out.Reviews) != boolCount(!badReviews) || len(out.Incidents) != boolCount(!badIncidents) || len(out.Interventions) != boolCount(!badInterventions) {
				t.Fatalf("failed source escaped or erased readable receipts: %+v", out)
			}
			if out.Evidence.Reviews.AtLimit || out.Evidence.Incidents.AtLimit || out.Evidence.Interventions.AtLimit {
				t.Fatalf("small or unavailable source marked at limit: %+v", out.Evidence)
			}
			if !reflect.DeepEqual(s.sessions, map[string]string{"reviews": "owned", "incidents": "owned", "interventions": "owned"}) || s.interventionLimit != 200 {
				t.Fatalf("receipt query scope changed: %+v, limit=%d", s.sessions, s.interventionLimit)
			}
			s.reviewErr, s.incidentErr, s.interventionErr, s.reviews.Degraded = nil, nil, nil, false
			recovered := readSessionOutcomeHistory(s, "owned")
			if !recovered.Evidence.Reviews.Available || !recovered.Evidence.Incidents.Available || !recovered.Evidence.Interventions.Available || len(recovered.Reviews) != 1 || len(recovered.Incidents) != 1 || len(recovered.Interventions) != 1 {
				t.Fatalf("new pass failed to recover receipts: %+v", recovered)
			}
			if recovered.Reviews[0].ID != "review" || recovered.Incidents[0].ID != "incident" || recovered.Interventions[0].Status != "failed" || recovered.Interventions[0].Verification != "unknown" {
				t.Fatalf("receipt facts changed: %+v", recovered)
			}
		})
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestOutcomeHistoryLimitsAndEmptySources(t *testing.T) {
	for _, counts := range [][3]int{{0, 0, 0}, {99, 99, 199}, {100, 100, 200}} {
		t.Run(fmt.Sprint(counts), func(t *testing.T) {
			s := &memoryOutcomeReader{
				reviews:       ReviewPage{Reviews: make([]model.ReviewRecord, counts[0])},
				incidents:     make([]model.IncidentReport, counts[1]),
				interventions: make([]model.InterventionReceipt, counts[2]), sessions: map[string]string{},
			}
			out := readSessionOutcomeHistory(s, "owned")
			want := SessionOutcomeEvidence{
				Guards:        ReportSourceEvidence{Available: true, Limit: 200},
				Reviews:       ReportSourceEvidence{Available: true, AtLimit: counts[0] == 100, Limit: 100},
				Incidents:     ReportSourceEvidence{Available: true, AtLimit: counts[1] == 100, Limit: 100},
				Interventions: ReportSourceEvidence{Available: true, AtLimit: counts[2] == 200, Limit: 200},
			}
			if out.Evidence != want || out.Reviews == nil || out.Incidents == nil || out.Interventions == nil {
				t.Fatalf("empty or bounded history misreported: %+v", out)
			}
		})
	}
}

func TestOutcomeHistoryRemovesScopeAuthorityWithoutMutatingReader(t *testing.T) {
	scopes := []model.ScopeChoice{{Kind: "exact", Expiry: "24h"}}
	s := &memoryOutcomeReader{reviews: ReviewPage{Reviews: []model.ReviewRecord{
		{ID: "newer", AvailableScopes: scopes, Decision: &model.ReviewDecisionReceipt{Action: "acknowledge"}},
		{ID: "older", AvailableScopes: scopes},
	}}, sessions: map[string]string{}}
	out := readSessionOutcomeHistory(s, "owned")
	if out.Reviews[0].ID != "newer" || out.Reviews[1].ID != "older" || out.Reviews[0].Decision.Action != "acknowledge" || out.Reviews[0].AvailableScopes != nil || out.Reviews[1].AvailableScopes != nil {
		t.Fatalf("history changed order, receipt, or retained action authority: %+v", out.Reviews)
	}
	if !reflect.DeepEqual(s.reviews.Reviews[0].AvailableScopes, scopes) || !reflect.DeepEqual(s.reviews.Reviews[1].AvailableScopes, scopes) {
		t.Fatal("history rendering mutated the reader's review rows")
	}
	out.Reviews[0].ID = "changed"
	if s.reviews.Reviews[0].ID != "newer" {
		t.Fatal("history shares its review row buffer with the reader")
	}
}
