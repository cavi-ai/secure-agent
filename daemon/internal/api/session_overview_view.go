package api

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/hookhealth"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type sessionOverviewEvidence struct {
	Session    model.Session
	Findings   []SessionFinding
	Truncated  bool
	HookHealth *hookhealth.Assessment
}

// readSessionOverviewEvidence maps retained session findings onto console
// titles. Selection, assessment, and the bounded identity read stay in the
// store. Live coverage and controls are gathered separately.
func readSessionOverviewEvidence(st *store.Store, id string) (sessionOverviewEvidence, error) {
	got, err := st.SessionFindings(id)
	if err != nil {
		return sessionOverviewEvidence{}, err
	}
	out := sessionOverviewEvidence{Session: got.Session, Findings: []SessionFinding{}, Truncated: got.Truncated}
	for _, f := range got.Findings {
		out.Findings = append(out.Findings, SessionFinding{ID: f.ID, Title: memoryRuleTitle(f.Rule), At: f.At, Assessment: f.Assessment})
	}
	return out, nil
}

// sessionOverviewLive is the current-control input for one overview.
// Coverage and Resources run only for an active or idle session when status
// is available, so ended sessions do not resolve live coverage or resources.
// HookIngestion describes the current daemon across all sessions.
type sessionOverviewLive struct {
	HookIngestion   *store.HookIngestionSnapshot
	Now             time.Time
	StatusAvailable bool
	Pending         []guard.Pending
	Coverage        func() []SessionCoverage
	Resources       func() *resource.Snapshot
}

func composeSessionOverview(id string, evidence sessionOverviewEvidence, live sessionOverviewLive) SessionOverview {
	sess := evidence.Session
	out := SessionOverview{
		SessionID:         id,
		ObservedAt:        live.Now,
		Requests:          []AttentionItem{},
		Findings:          evidence.Findings,
		FindingsTruncated: evidence.Truncated,
		HookHealth:        evidence.HookHealth,
		HookIngestion:     live.HookIngestion,
	}
	for _, p := range live.Pending {
		if p.SessionID == id {
			out.Requests = append(out.Requests, AttentionItem{Kind: "guard", ID: p.ID, Title: "Access request", Detail: p.Tool + " wants access to " + p.Path, Path: p.Path, Rule: p.RuleID, ScopeText: p.ScopeText, ReaderExe: p.ReaderExe, AvailableScopes: p.AvailableScopes})
		}
	}
	if !live.StatusAvailable || (sess.Status != model.SessionActive && sess.Status != model.SessionIdle) || live.Coverage == nil {
		return out
	}
	for _, row := range live.Coverage() {
		if row.SessionID == id {
			copy := row
			out.Coverage = &copy
			break
		}
	}
	// Coverage's strict live-root match excludes ambiguous durable IDs.
	// Resource ownership additionally needs the same PID AND start time.
	start, parseErr := time.Parse(time.RFC3339Nano, sess.RootStartedAt)
	if out.Coverage == nil || parseErr != nil || live.Resources == nil {
		return out
	}
	snapshot := live.Resources()
	if snapshot == nil {
		return out
	}
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
	return out
}
