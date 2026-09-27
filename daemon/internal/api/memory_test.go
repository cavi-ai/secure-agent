package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestSessionMemoryRedaction(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	st.UpsertSession(model.Session{ID: "s1", RootPID: 100, RootStartedAt: started.Format(time.RFC3339Nano), StartedAt: started, LastSeenAt: now})
	hostile := "<script>SECRET-RAW</script>"
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now, SessionID: "s1", Path: hostile, Detail: hostile})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(time.Nanosecond), SessionID: "s1", Path: "guard-deny:cloud-creds", Detail: "secret-guard:deny"})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(2 * time.Nanosecond), SessionID: "s1", Path: "guard-deny:cloud-creds", Detail: "secret-guard-broker:deny"})
	st.PutFlag(model.Flag{ID: "f1", Rule: hostile, Severity: 3, TS: now, SessionID: "s1", Evidence: []model.EvidenceItem{{Kind: "text", Text: hostile}}})
	st.PutIncident(model.IncidentReport{ID: "i1", Rule: hostile, SessionID: "s1", Timestamp: now, Summary: hostile})
	st.PutGuardDecision(store.GuardDecision{ID: "g1", SessionID: "s1", RuleID: hostile, Verdict: "deny", Scope: "once", At: now.Format(time.RFC3339Nano)})
	st.PutResourceEpisode(resource.Episode{CapturedAt: now, Severity: "warning", DiagnosisCodes: []string{hostile}, Session: resource.Session{Key: "100:" + strconv.FormatInt(started.UnixNano(), 10), RootPID: 100, RootStartedAt: started, Workspace: hostile, Kind: "agent"}})
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	w := httptest.NewRecorder()
	a.handleSessionSubpath(w, httptest.NewRequest(http.MethodGet, "/sessions/s1/memory", nil))
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), hostile) {
		t.Fatalf("raw payload leaked: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "secret-guard-broker") {
		t.Fatalf("broker audit leaked: %s", w.Body.String())
	}
	var out struct {
		Rows []struct {
			Kind string `json:"kind"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	var direct, resources int
	for _, row := range out.Rows {
		if row.Kind == "guard-audit" {
			direct++
		}
		if row.Kind == "resource" {
			resources++
		}
	}
	if direct != 1 {
		t.Fatalf("direct guard audits=%d, want 1: %s", direct, w.Body.String())
	}
	if resources != 1 {
		t.Fatalf("resource rows=%d, want 1: %s", resources, w.Body.String())
	}
}

func TestSessionMemoryErrors(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", StartedAt: now, LastSeenAt: now})
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	for _, tc := range []struct {
		path string
		want int
	}{{"/sessions/s1/memory?limit=bad", 400}, {"/sessions/s1/memory?limit=0", 400}, {"/sessions/s1/memory?limit=", 400}, {"/sessions/s1/memory?before=garbage", 400}, {"/sessions/s1/memory?before=", 400}, {"/sessions/missing/memory", 404}} {
		w := httptest.NewRecorder()
		a.handleSessionSubpath(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s: HTTP %d want %d", tc.path, w.Code, tc.want)
		}
	}
}

func TestSessionMemoryPagination(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	st.UpsertSession(model.Session{ID: "s1", StartedAt: now, LastSeenAt: now})
	for i := 0; i < 3; i++ {
		st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(time.Duration(i) * time.Nanosecond), SessionID: "s1"})
	}
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	first := httptest.NewRecorder()
	a.handleSessionSubpath(first, httptest.NewRequest(http.MethodGet, "/sessions/s1/memory?limit=2", nil))
	if first.Code != 200 {
		t.Fatalf("first HTTP %d: %s", first.Code, first.Body.String())
	}
	var p1 memoryResponse
	if err := json.Unmarshal(first.Body.Bytes(), &p1); err != nil {
		t.Fatal(err)
	}
	if len(p1.Rows) != 2 || !p1.HasEarlier || p1.NextCursor == "" {
		t.Fatalf("first page: %+v", p1)
	}
	second := httptest.NewRecorder()
	a.handleSessionSubpath(second, httptest.NewRequest(http.MethodGet, "/sessions/s1/memory?limit=2&before="+p1.NextCursor, nil))
	if second.Code != 200 {
		t.Fatalf("second HTTP %d: %s", second.Code, second.Body.String())
	}
	var p2 memoryResponse
	if err := json.Unmarshal(second.Body.Bytes(), &p2); err != nil {
		t.Fatal(err)
	}
	if len(p2.Rows) != 1 || p2.HasEarlier || p2.Rows[0].ID == p1.Rows[0].ID || !p2.Rows[0].At.Before(p1.Rows[0].At) {
		t.Fatalf("second page: %+v first: %+v", p2, p1)
	}
}
