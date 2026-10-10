package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
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
	ExpectedRuleID   string              `json:"expected_rule_id,omitempty"`
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
	writeJSON(w, map[string]any{"episodes": a.egressEpisodeViews(), "non_candidate_limit": 100})
}

// egressCandidate: a recurring, attributable episode that no expected-egress
// rule explains is a decision for the operator.
func egressCandidate(e store.EgressEpisode, ruleID string) bool {
	return e.Recurring && e.Scope.Agent != "" && e.Scope.Agent != "unknown" && ruleID == ""
}

// egressEpisodeViews serves the read API: candidates first, then up to 100
// other episodes.
func (a *API) egressEpisodeViews() []egressEpisodeView {
	if a.store == nil {
		return []egressEpisodeView{}
	}
	return readEgressEpisodeViews(a.store)
}

type egressEpisodeStore interface {
	ExpectedEgressMatcher() func(store.EgressEpisode) string
	ListEgressEpisodesForReview() []store.EgressEpisode
	AdvisorVerdictsFor([]string, string) (map[string]model.AdvisorVerdict, error)
}

func readEgressEpisodeViews(st egressEpisodeStore) []egressEpisodeView {
	candidates := make([]egressEpisodeView, 0)
	other := make([]egressEpisodeView, 0, 100)
	if st == nil {
		return other
	}
	match := st.ExpectedEgressMatcher()
	for _, e := range st.ListEgressEpisodesForReview() {
		if !e.Recurring && len(other) >= 100 {
			continue
		}
		ruleID := match(e)
		view := egressEpisodeView{ID: e.ID, Observed: e, Expected: ruleID != "", ExpectedRuleID: ruleID, Candidate: egressCandidate(e, ruleID)}
		if view.Candidate {
			candidates = append(candidates, view)
		} else if len(other) < 100 {
			other = append(other, view)
		}
	}
	views := append(candidates, other...)
	subjectIDs := make([]string, len(views))
	for i, view := range views {
		subjectIDs[i] = advisor.EgressSubjectID(view.ID)
	}
	// Optional advice may be partial; the store retains health for the whole batch.
	verdicts, _ := st.AdvisorVerdictsFor(subjectIDs, "egress")
	for i := range views {
		view := &views[i]
		if v, ok := verdicts[subjectIDs[i]]; ok && v.Assessment == advisor.EgressEvidenceKey(view.Observed) {
			view.AdvisorInference = &egressInference{PossiblePurpose: v.Rationale, Confidence: v.Confidence, CreatedAt: v.CreatedAt}
		}
	}
	return views
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
