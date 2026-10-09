package api

import (
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
	sess, found, err := a.store.GetSessionResult(id)
	if err != nil {
		http.Error(w, "session status unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	const findingCap = 20
	flags, err := a.store.QueryFlagsResult(store.FlagFilter{SessionID: id, Limit: findingCap + 1})
	if err != nil {
		http.Error(w, "session findings unavailable", http.StatusServiceUnavailable)
		return
	}
	out := SessionOverview{SessionID: id, ObservedAt: time.Now().UTC(), Requests: []AttentionItem{}, Findings: []SessionFinding{}, FindingsTruncated: len(flags) > findingCap}
	for _, f := range flags[:min(len(flags), findingCap)] {
		out.Findings = append(out.Findings, SessionFinding{ID: f.ID, Title: memoryRuleTitle(f.Rule), At: f.TS, Assessment: assessmentForFlag(f)})
	}
	if a.guardBroker != nil {
		for _, p := range a.guardBroker.Pending() {
			if p.SessionID == id {
				out.Requests = append(out.Requests, AttentionItem{Kind: "guard", ID: p.ID, Title: "Access request", Detail: p.Tool + " wants access to " + p.Path, Path: p.Path, Rule: p.RuleID, ScopeText: p.ScopeText, ReaderExe: p.ReaderExe, AvailableScopes: p.AvailableScopes})
			}
		}
	}
	if a.statusFn != nil && (sess.Status == model.SessionActive || sess.Status == model.SessionIdle) {
		st := a.evidenceStatus(a.currentStatus())
		if st.Coverage != nil {
			for _, row := range st.Coverage.Sessions {
				if row.SessionID == id {
					copy := row
					out.Coverage = &copy
					break
				}
			}
		}
		// Coverage's strict live-root match excludes ambiguous durable IDs.
		// Resource ownership additionally needs the same PID AND start time.
		start, parseErr := time.Parse(time.RFC3339Nano, sess.RootStartedAt)
		if out.Coverage != nil && parseErr == nil && a.resources != nil {
			snapshot := a.resources()
			matches := 0
			for _, family := range snapshot.Sessions {
				if family.RootPID == sess.RootPID && family.RootStartedAt.Equal(start) && family.Name == sess.Harness {
					matches++
					out.Resources = &SessionResources{Key: family.Key, ObservedAt: snapshot.ObservedAt, RSSBytes: family.RSSBytes, CPUPercent: family.CPUPercent, ProcessCount: family.ProcessCount, Diagnoses: family.Diagnoses, Control: family.Control}
				}
			}
			if matches != 1 {
				out.Resources = nil
			}
		}
	}
	writeJSON(w, out)
}
