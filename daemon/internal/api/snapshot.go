package api

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Snapshot is the console hot path in one payload: everything that must
// refresh when a bus event lands. Slow panels (fleet, audit, sources,
// rollup, uninspected, notify rules) stay on their own 30s cadence.
type Snapshot struct {
	Status  Status           `json:"status"`
	Flags   []model.Flag     `json:"flags"`
	Reviews store.ReviewPage `json:"reviews"`
	// Patterns are the repeating findings of the same 24h (at least 3 flags
	// each); the console renders them instead of the flags they cover.
	Patterns []model.Pattern `json:"patterns"`
	// Routine are the same reads across agents (at least 3 flags spanning
	// agents or files); the console renders one decision for each.
	Routine     []model.RoutineGroup `json:"routine"`
	Incidents   any                  `json:"incidents"`
	Events      []event.Event        `json:"events"`
	Posture     Posture              `json:"posture"`
	Suggestions []Suggestion         `json:"suggestions"`
	Mutes       []MutePair           `json:"mutes"`
	// Sessions is the durable session spine (live and recently ended) — the
	// Sessions tab renders from this, not from process-tree guesswork.
	Sessions []model.Session `json:"sessions"`
}

type snapshotIncident struct {
	model.IncidentReport
	Workflow store.IncidentWorkflow `json:"workflow"`
}

func (a *API) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := a.currentSnapshot()
	if err != nil {
		http.Error(w, "snapshot data unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, snapshot)
}

func (a *API) currentSnapshot() (Snapshot, error) {
	sessions, err := a.store.ListSessionsResult(store.SessionFilter{Limit: 100})
	if err != nil {
		return Snapshot{}, err
	}
	events, err := a.store.QueryEventsResult(store.EventFilter{Limit: 50})
	if err != nil {
		return Snapshot{}, err
	}
	return a.snapshotWithSessions(sessions, events)
}

func (a *API) incidentListResult(limit int) ([]snapshotIncident, error) {
	incidents, err := a.store.RecentIncidentsResult(limit)
	if err != nil {
		return nil, err
	}
	out := make([]snapshotIncident, 0, len(incidents))
	for i := range incidents {
		wf, found, err := a.store.IncidentStatusResult(incidents[i].ID)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("incident workflow unavailable")
		}
		out = append(out, snapshotIncident{IncidentReport: incidents[i], Workflow: wf})
	}
	return out, nil
}

func (a *API) snapshotWithSessions(sessions []model.Session, events []event.Event) (Snapshot, error) {
	out, err := a.incidentListResult(10)
	if err != nil {
		return Snapshot{}, err
	}
	flags, err := a.store.QueryFlagsResult(store.FlagFilter{
		Unacted: true,
		Since:   time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		Limit:   200,
	})
	if err != nil {
		return Snapshot{}, err
	}
	for i := range flags {
		flags[i].Title = humanFlagTitle(flags[i].Rule)
		flags[i].ReviewID, _ = a.store.FindingReviewID(flags[i].ID)
	}
	a.stampExplains(flags)
	since := time.Now().Add(-24 * time.Hour)
	patterns, err := a.computePatternsResult(since, patternDefaultMin)
	if err != nil {
		return Snapshot{}, err
	}
	routine, err := a.routineGroupsResult(since)
	if err != nil {
		return Snapshot{}, err
	}
	reviews, reviewErr := a.store.ListFindingReviews("", 100)
	if reviewErr != nil {
		reviews.Degraded = true
	}
	return Snapshot{
		Status:      a.currentStatus(),
		Flags:       flags,
		Reviews:     reviews,
		Patterns:    patterns,
		Routine:     routine,
		Incidents:   out,
		Events:      priceClassed(events),
		Posture:     a.postureWith(patterns, routine),
		Suggestions: a.suggestionList(),
		Mutes:       a.mutePairs(),
		Sessions:    sessions,
	}, nil
}

func (a *API) mutePairs() []MutePair {
	out := []MutePair{}
	if a.mutes == nil {
		return out
	}
	for rule, mutes := range a.mutes.Load() {
		for _, m := range mutes {
			out = append(out, MutePair{Rule: rule, Host: m.Host, Agent: m.Agent, Title: humanFlagTitle(rule)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Agent < out[j].Agent
	})
	return out
}

func (a *API) suggestionList() []Suggestion {
	out := []Suggestion{}
	if a.correlator == nil {
		return out
	}
	for _, e := range a.correlator.UninspectedEgressSummary() {
		if e.Count < minSuggestionCount || e.Infra != "" || e.Identity.Class == "vendor" || e.AgentKind == config.AgentKindInfra {
			// Rare pairs, known CDN/cloud carriers, the agents' own vendors
			// (rolled up in the drill-down with their own bulk action) and
			// infra families (not agents) are never "approve this endpoint"
			// suggestions — suggestions exist for judgment calls.
			continue
		}
		sg := Suggestion{Agent: e.Agent, Host: e.Host, Count: e.Count, Identity: e.Identity}
		if v, ok := a.store.AdvisorVerdictFor("host:"+e.Agent+"|"+e.Host, "host"); ok {
			sg.Assessment = v.Assessment
			sg.Rationale = v.Rationale
			sg.Confidence = v.Confidence
		}
		out = append(out, sg)
	}
	return out
}
