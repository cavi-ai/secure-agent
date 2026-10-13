package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// SessionOverview keeps current controls separate from retained evidence.
// Attribution is never inferred from a shared workspace or harness name.
type SessionOverview struct {
	SessionID         string            `json:"session_id"`
	ObservedAt        time.Time         `json:"observed_at"`
	Requests          []AttentionItem   `json:"requests"`
	Findings          []SessionFinding  `json:"findings"`
	FindingsTruncated bool              `json:"findings_truncated"`
	Coverage          *SessionCoverage  `json:"coverage"`
	Resources         *SessionResources `json:"resources"`
}

type SessionFinding struct {
	ID         string                  `json:"id"`
	Title      string                  `json:"title"`
	At         time.Time               `json:"at"`
	Assessment model.FindingAssessment `json:"assessment"`
}

// Process details and history remain on the existing resource surface.
type SessionResources struct {
	Key          string                   `json:"key"`
	ObservedAt   time.Time                `json:"observed_at"`
	RSSBytes     uint64                   `json:"rss_bytes"`
	CPUPercent   float64                  `json:"cpu_percent"`
	ProcessCount int                      `json:"process_count"`
	Diagnoses    []resource.Diagnosis     `json:"diagnoses"`
	Control      *resource.SessionControl `json:"control,omitempty"`
}

func (a *API) serveSessionOverview(w http.ResponseWriter, r *http.Request, id string) {
	evidence, err := readSessionOverviewEvidence(a.store, id)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrSessionFindingsMissing):
			http.Error(w, "session not found", http.StatusNotFound)
		case errors.Is(err, store.ErrSessionFindingsIdentity):
			http.Error(w, "session status unavailable", http.StatusServiceUnavailable)
		default:
			http.Error(w, "session findings unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	live := sessionOverviewLive{Now: time.Now().UTC(), StatusAvailable: a.statusFn != nil}
	if a.guardBroker != nil {
		live.Pending = a.guardBroker.Pending()
	}
	if live.StatusAvailable {
		live.Coverage = func() []SessionCoverage {
			st := a.currentStatus()
			if st.Coverage == nil {
				return nil
			}
			return st.Coverage.Sessions
		}
		live.Resources = func() *resource.Snapshot {
			if a.resources == nil {
				return nil
			}
			snapshot := a.resources()
			return &snapshot
		}
	}
	writeJSON(w, composeSessionOverview(id, evidence, live))
}
