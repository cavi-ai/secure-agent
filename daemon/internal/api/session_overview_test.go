package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func overviewJSON(t *testing.T, a *API, id string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/sessions/"+id+"/overview", nil))
	if w.Code != 200 {
		t.Fatalf("overview HTTP %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSessionOverviewKeepsEvidenceAndLiveIdentitySeparate(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	start := now.Add(-time.Hour)
	for i, id := range []string{"own", "sibling"} {
		st.UpsertSession(model.Session{ID: id, Harness: "claude", RootPID: int32(40 + i), RootStartedAt: start.Format(time.RFC3339Nano), Workspace: "/same", StartedAt: start, LastSeenAt: now, Status: model.SessionActive})
		st.PutFlag(model.Flag{ID: id, SessionID: id, Agent: "claude", TS: now, Rule: "sensitive-read-then-connect", Severity: 3, Acknowledged: true})
	}
	st.PutFlag(model.Flag{ID: "unknown", Agent: "claude", TS: now, Rule: "sensitive-read-then-connect", Severity: 3})
	st.PutEvent(event.Event{Kind: event.KindToolCall, SessionID: "own", TS: now, ToolName: "Read"})

	rootStart := start

	a := newTestAPI(Deps{SocketPath: "", Store: st, Killer: nil, Status: func() Status {
		return Status{Running: true, Agents: []AgentSummary{{PID: 40, RootPID: 40, Name: "claude", StartedAt: start.Format(time.RFC3339Nano)}}}
	}, Resources: func() resource.Snapshot {
		return resource.Snapshot{Sessions: []resource.Session{{Key: "root", RootPID: 40, RootStartedAt: rootStart, Name: "claude", RSSBytes: 1024, ProcessCount: 2}}}
	}})
	out := overviewJSON(t, a, "own")
	findings := out["findings"].([]any)
	if len(findings) != 1 || findings[0].(map[string]any)["id"] != "own" {
		t.Fatalf("borrowed findings: %+v", out)
	}
	assessment := findings[0].(map[string]any)["assessment"].(map[string]any)
	if assessment["review_state"] != "reviewed" || assessment["residual_risk"] == "" {
		t.Fatalf("review erased risk: %+v", assessment)
	}
	if out["coverage"].(map[string]any)["session_id"] != "own" || out["resources"].(map[string]any)["key"] != "root" {
		t.Fatalf("own live evidence missing: %+v", out)
	}
	rootStart = now
	if out = overviewJSON(t, a, "own"); out["resources"] != nil {
		t.Fatalf("resource evidence borrowed after PID reuse: %+v", out)
	}
	st.EndSession("own", now)
	rootStart = start
	if out = overviewJSON(t, a, "own"); out["resources"] != nil || out["coverage"] != nil {
		t.Fatalf("ended session claimed live coverage: %+v", out)
	}
}

func TestSessionOverviewGuardUsesExplicitSessionID(t *testing.T) {
	a, _ := scopedGuardAPI(t)
	p, done := enqueueScopeGuard(t, a, "")
	out := overviewJSON(t, a, "session")
	requests := out["requests"].([]any)
	if len(requests) != 1 || requests[0].(map[string]any)["id"] != p.ID {
		t.Fatalf("pending request missing: %+v", out)
	}
	a.store.UpsertSession(model.Session{ID: "sibling", Harness: "codex", StartedAt: time.Now(), Status: model.SessionActive})
	if got := overviewJSON(t, a, "sibling")["requests"].([]any); len(got) != 0 {
		t.Fatalf("sibling borrowed request: %+v", got)
	}
	a.guardBroker.Resolve(p.ID, guard.Decision{Verdict: "deny", Scope: "once"})
	<-done
}

func TestSessionOverviewBoundedFindingsAndReadFailure(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s", StartedAt: now, Status: model.SessionActive})
	for i := 0; i < 24; i++ {
		st.PutFlag(model.Flag{ID: fmt.Sprint(i), SessionID: "s", Rule: "sensitive-read-then-connect", TS: now, Severity: 3})
	}
	a := newTestAPI(Deps{SocketPath: "", Store: st, Killer: nil, Status: func() Status { return Status{Running: true} }})
	out := overviewJSON(t, a, "s")
	if len(out["findings"].([]any)) != 20 || out["findings_truncated"] != true {
		t.Fatalf("unbounded or hidden limit: %+v", out)
	}
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/sessions/missing/overview", nil))
	if w.Code != 404 {
		t.Fatalf("missing: %d", w.Code)
	}
	st.Close()
	w = httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/sessions/s/overview", nil))
	if w.Code != 503 {
		t.Fatalf("failed read presented as absence: %d %s", w.Code, w.Body.String())
	}
}

func TestSessionOverviewFindingsFailureAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overview.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	st.UpsertSession(model.Session{ID: "session", StartedAt: now, Status: model.SessionEnded})
	if _, err := st.PutFlag(model.Flag{ID: "flag", SessionID: "session", PID: 1, Rule: readConnectRule, Severity: 3, TS: now}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE flags SET pid='invalid' WHERE id='flag'"); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI(Deps{SocketPath: "", Store: st, Killer: nil, Status: func() Status { return Status{Running: true} }})
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/sessions/session/overview", nil))
	if w.Code != 503 || strings.TrimSpace(w.Body.String()) != "session findings unavailable" {
		t.Fatalf("findings failure misclassified or leaked storage details: %d %s", w.Code, w.Body.String())
	}
	if _, err := db.Exec("UPDATE flags SET pid=1 WHERE id='flag'"); err != nil {
		t.Fatal(err)
	}
	if findings := overviewJSON(t, a, "session")["findings"].([]any); len(findings) != 1 || findings[0].(map[string]any)["id"] != "flag" {
		t.Fatalf("recovered findings missing: %+v", findings)
	}
}
