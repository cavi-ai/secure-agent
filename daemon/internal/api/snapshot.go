package api

import (
	"net/http"
	"sort"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Snapshot is the console hot path in one payload: everything that must
// refresh when a bus event lands. Slow panels (fleet, audit, sources,
// rollup, uninspected, notify rules) stay on their own 30s cadence.
type Snapshot struct {
	Status      Status        `json:"status"`
	Flags       []model.Flag  `json:"flags"`
	Incidents   any           `json:"incidents"`
	Events      []event.Event `json:"events"`
	Posture     Posture       `json:"posture"`
	Suggestions []Suggestion  `json:"suggestions"`
	Mutes       []MutePair    `json:"mutes"`
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
	writeJSON(w, a.currentSnapshot())
}

func (a *API) currentSnapshot() Snapshot {
	incidents := a.store.RecentIncidents(10)
	out := make([]snapshotIncident, 0, len(incidents))
	for i := range incidents {
		wf, _ := a.store.IncidentStatus(incidents[i].ID)
		out = append(out, snapshotIncident{IncidentReport: incidents[i], Workflow: wf})
	}
	return Snapshot{
		Status:      a.currentStatus(),
		Flags:       a.store.QueryFlags(store.FlagFilter{Limit: 20}),
		Incidents:   out,
		Events:      a.store.QueryEvents(store.EventFilter{Limit: 50}),
		Posture:     a.computePosture(),
		Suggestions: a.suggestionList(),
		Mutes:       a.mutePairs(),
	}
}

func (a *API) mutePairs() []MutePair {
	out := []MutePair{}
	if a.mutes == nil {
		return out
	}
	for rule, hosts := range a.mutes.Load() {
		for _, h := range hosts {
			out = append(out, MutePair{Rule: rule, Host: h})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func (a *API) suggestionList() []Suggestion {
	out := []Suggestion{}
	if a.correlator == nil {
		return out
	}
	for _, e := range a.correlator.UninspectedEgressSummary() {
		if e.Count < minSuggestionCount {
			continue
		}
		sg := Suggestion{Agent: e.Agent, Host: e.Host, Count: e.Count}
		if v, ok := a.store.AdvisorVerdictFor("host:"+e.Agent+"|"+e.Host, "host"); ok {
			sg.Assessment = v.Assessment
			sg.Rationale = v.Rationale
			sg.Confidence = v.Confidence
		}
		out = append(out, sg)
	}
	return out
}
