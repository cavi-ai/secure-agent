package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type coverageTestPath struct {
	State    string
	LastSeen string `json:"last_seen"`
}
type coverageTestSession struct {
	SessionID             string `json:"session_id"`
	RootPID               int32  `json:"root_pid"`
	Guard, Trace, Payload coverageTestPath
}

func coverageTestRows(t *testing.T, a *API) []coverageTestSession {
	t.Helper()
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	if w.Code != 200 {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Coverage struct{ Sessions []coverageTestSession }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Coverage.Sessions
}

func TestSessionCoverageNeverBorrowsSiblingEvidence(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	start := now.Add(-time.Hour)
	agents := []AgentSummary{}
	for i, id := range []string{"observed", "silent"} {
		pid := int32(40 + i)
		if err := st.UpsertSession(model.Session{ID: id, Harness: "claude", Workspace: "/work/" + id, RootPID: pid, RootStartedAt: start.Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: now, Status: model.SessionActive}); err != nil {
			t.Fatal(err)
		}
		agents = append(agents, AgentSummary{PID: pid, RootPID: pid, Name: "claude", StartedAt: start.Format(time.RFC3339Nano)})
	}
	st.PutEvent(event.Event{Kind: event.KindPluginAction, SessionID: "observed", TS: now, Detail: "secret-guard:deny"})
	st.PutEvent(event.Event{Kind: event.KindToolCall, SessionID: "observed", TS: now, ToolName: "Read", CallID: "call"})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, SessionID: "silent", TS: now, Detail: "session-start"})
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true, Agents: agents} })
	rows := coverageTestRows(t, a)
	if len(rows) != 2 {
		t.Fatalf("want two independent session rows, got %+v", rows)
	}
	byID := map[string]coverageTestSession{}
	for _, row := range rows {
		byID[row.SessionID] = row
	}
	if byID["observed"].Guard.LastSeen == "" || byID["observed"].Trace.LastSeen == "" {
		t.Fatalf("own observations missing: %+v", rows)
	}
	if byID["silent"].Guard.LastSeen != "" || byID["silent"].Trace.LastSeen != "" {
		t.Fatalf("sibling activity or handshake credited as guarding: %+v", rows)
	}
}

func TestSessionCoverageRejectsReusedPIDAndUnattributedEvidence(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	old := now.Add(-time.Hour)
	st.UpsertSession(model.Session{ID: "old", Harness: "claude", RootPID: 42, RootStartedAt: old.Format(time.RFC3339Nano), StartedAt: old, LastSeenAt: now, Status: model.SessionActive})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, SessionID: "old", PID: 42, TS: now, Detail: "secret-guard:deny"})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, PID: 42, TS: now, Detail: "secret-guard:deny"})
	a := newTestAPI("", st, nil, func() Status {
		return Status{Running: true, Agents: []AgentSummary{{PID: 42, RootPID: 42, Name: "claude", StartedAt: now.Format(time.RFC3339Nano)}}}
	})
	rows := coverageTestRows(t, a)
	if len(rows) != 1 || rows[0].SessionID != "" || rows[0].Guard.LastSeen != "" {
		t.Fatalf("PID reuse or unknown attribution borrowed evidence: %+v", rows)
	}
}

func TestSessionCoverageUsesInstantOrderForGuardEvidence(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	start := now.Add(-time.Hour)
	st.UpsertSession(model.Session{ID: "s", Harness: "claude", RootPID: 42, RootStartedAt: start.Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: now, Status: model.SessionActive})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, SessionID: "s", TS: now, Detail: "secret-guard:deny"})
	st.PutGuardDecisionForTest(store.GuardDecision{ID: "decision", SessionID: "s", At: now.Add(time.Nanosecond).Format(time.RFC3339Nano), Verdict: "deny", Scope: "once"})
	a := newTestAPI("", st, nil, func() Status {
		return Status{Agents: []AgentSummary{{PID: 42, RootPID: 42, Name: "claude", StartedAt: start.Format(time.RFC3339Nano)}}}
	})
	rows := coverageTestRows(t, a)
	if len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}
	at, err := time.Parse(time.RFC3339Nano, rows[0].Guard.LastSeen)
	if err != nil || !at.Equal(now.Add(time.Nanosecond)) {
		t.Fatalf("latest instant lost to string order: %q", rows[0].Guard.LastSeen)
	}
}

func TestSessionCoverageExcludesFutureAndPreSessionEvidenceAndKeepsStaleFacts(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	start := now.Add(-time.Hour)
	st.UpsertSession(model.Session{ID: "s", Harness: "claude", RootPID: 42, RootStartedAt: start.Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: now, Status: model.SessionActive})
	for _, at := range []time.Time{start.Add(-time.Minute), now.Add(time.Hour)} {
		st.PutEvent(event.Event{Kind: event.KindPluginAction, SessionID: "s", TS: at, Detail: "secret-guard:deny"})
	}
	a := newTestAPI("", st, nil, func() Status {
		return Status{Agents: []AgentSummary{{PID: 42, RootPID: 42, Name: "claude", StartedAt: start.Format(time.RFC3339Nano)}}}
	})
	if rows := coverageTestRows(t, a); len(rows) != 1 || rows[0].Guard.LastSeen != "" {
		t.Fatalf("invalid time window credited: %+v", rows)
	}
	st.PutEvent(event.Event{Kind: event.KindPluginAction, SessionID: "s", TS: now, Detail: "secret-guard:deny"})
	a.sessionCoverage.at = time.Time{}
	before := coverageTestRows(t, a)
	if before[0].Guard.LastSeen == "" {
		t.Fatal("valid own evidence absent")
	}
	st.Close()
	a.sessionCoverage.at = time.Time{}
	after := coverageTestRows(t, a)
	if after[0].Guard.LastSeen != before[0].Guard.LastSeen || after[0].Guard.State != "stale" {
		t.Fatalf("last-known evidence erased or presented as fresh: %+v", after)
	}
}

func TestSessionCoverageDoesNotCountAnInspectionGapAsPayloadInspection(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	start := now.Add(-time.Hour)
	st.UpsertSession(model.Session{ID: "s", Harness: "claude", RootPID: 42, RootStartedAt: start.Format(time.RFC3339Nano), StartedAt: start, LastSeenAt: now, Status: model.SessionActive})
	st.PutEvent(event.Event{Kind: event.KindProxyHit, SessionID: "s", TS: now, Detail: "proxy-inspection-incomplete:body-limit"})
	a := newTestAPI("", st, nil, func() Status {
		return Status{ProxyEnabled: true, Agents: []AgentSummary{{PID: 42, RootPID: 42, Name: "claude", StartedAt: start.Format(time.RFC3339Nano)}}}
	})
	rows := coverageTestRows(t, a)
	if rows[0].Payload.LastSeen != "" || rows[0].Payload.State == "observed" {
		t.Fatalf("inspection failure credited as inspected payload: %+v", rows[0].Payload)
	}
	st.PutEvent(event.Event{Kind: event.KindProxyHit, SessionID: "s", TS: now, Detail: "proxy-secret-leak:aws-key"})
	a.sessionCoverage.at = time.Time{}
	if rows := coverageTestRows(t, a); rows[0].Payload.LastSeen == "" {
		t.Fatal("actual inspected match absent")
	}
}
