package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type egressInference struct {
	PossiblePurpose string    `json:"possible_purpose"`
	Confidence      float64   `json:"confidence"`
	CreatedAt       time.Time `json:"created_at"`
}

type egressEpisodeView struct {
	ID               string              `json:"id"`
	Observed         store.EgressEpisode `json:"observed"`
	Expected         bool                `json:"expected"`
	Candidate        bool                `json:"candidate"`
	AdvisorInference *egressInference    `json:"advisor_inference,omitempty"`
}

func (a *API) handleEgressEpisodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"episodes": a.egressEpisodeViews()})
}

// egressEpisodeViews is shared by the read API and Home's decision projection.
func (a *API) egressEpisodeViews() []egressEpisodeView {
	rows := make([]egressEpisodeView, 0)
	if a.store == nil {
		return rows
	}
	for _, e := range a.store.ListEgressEpisodes(100) {
		expected := a.store.ExpectedEgressMatch(store.EgressObservation{Scope: e.Scope, Host: e.Host, Protocol: e.Protocol, Port: e.Port})
		view := egressEpisodeView{ID: e.ID, Observed: e, Expected: expected, Candidate: e.Recurring && e.Scope.Agent != "" && e.Scope.Agent != "unknown" && !expected}
		if v, ok := a.store.AdvisorVerdictFor(advisor.EgressSubjectID(e.ID), "egress"); ok && v.Assessment == advisor.EgressEvidenceKey(e) {
			view.AdvisorInference = &egressInference{PossiblePurpose: v.Rationale, Confidence: v.Confidence, CreatedAt: v.CreatedAt}
		}
		rows = append(rows, view)
	}
	return rows
}

func (a *API) handleEgressEpisodeSubpath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/egress/episodes/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[1] != "assess" || len(parts[0]) != 32 || strings.Trim(parts[0], "0123456789abcdef") != "" {
		http.NotFound(w, r)
		return
	}
	e, ok := a.store.GetEgressEpisode(parts[0])
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !e.Recurring || e.Scope.Agent == "" || e.Scope.Agent == "unknown" {
		http.Error(w, "not a recurring candidate", http.StatusConflict)
		return
	}
	if v, ok := a.store.AdvisorVerdictFor(advisor.EgressSubjectID(e.ID), "egress"); ok && v.Assessment == advisor.EgressEvidenceKey(e) {
		writeJSON(w, map[string]any{"status": "cached"})
		return
	}
	if a.egressAdvisor == nil {
		http.Error(w, "advisor unavailable", http.StatusServiceUnavailable)
		return
	}
	if !a.egressAdvisor(e) {
		http.Error(w, "advisor queue unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"status": "queued"})
}
