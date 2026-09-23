package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// /egress/uninspected rows carry who the host is, when it started, and the
// session that reached it.
func TestUninspectedEgressRows(t *testing.T) {
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, allowlistProcSource{})
	tg.Refresh()
	cr := correlate.New(tg, sensitive.New(cfg), cfg)
	first := time.Now().Add(-time.Hour)
	cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 42, TS: first, RemoteHost: "160.79.104.10", RemotePort: 443, SessionID: "sess-a"})
	cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 42, TS: time.Now(), RemoteHost: "160.79.104.10", RemotePort: 443, SessionID: "sess-b"})

	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	a.correlator = cr
	rec := httptest.NewRecorder()
	a.handleUninspectedEgress(rec, httptest.NewRequest(http.MethodGet, "/egress/uninspected", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("rows = %s", rec.Body.String())
	}
	for _, k := range []string{"identity", "first_seen", "session_id"} {
		if _, ok := raw[0][k]; !ok {
			t.Fatalf("row missing %q: %s", k, rec.Body.String())
		}
	}
	var rows []UninspectedEndpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	r := rows[0]
	if r.Identity.Org != "Anthropic" || r.SessionID != "sess-b" || r.FirstSeen == nil || r.FirstSeen.Unix() != first.Unix() {
		t.Fatalf("row = %+v (first_seen %v)", r, r.FirstSeen)
	}
}

// The endpoint drawer resolves a session by id, not from a list page: the
// oldest of 1,200 sessions is still attributed.
func TestEndpointDetailFindsSessionBeyondListLimit(t *testing.T) {
	st := testStore(t)
	base := time.Now().Add(-1200 * time.Minute)
	for i := 0; i < 1200; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		st.UpsertSession(model.Session{ID: fmt.Sprintf("proc-%d", i), Harness: "openclaw",
			StartedAt: at, LastSeenAt: at, Status: model.SessionActive, Confidence: model.ConfHook})
	}
	host := "203.0.113.7"
	st.PutEvent(event.Event{Kind: event.KindConnOpen, TS: time.Now(), SessionID: "proc-0", RemoteHost: host, RemotePort: 443})

	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	rec := httptest.NewRecorder()
	a.handleEndpointDetail(rec, httptest.NewRequest(http.MethodGet, "/egress/endpoint?host="+host, nil))
	var d EndpointDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Sessions) != 1 || d.Sessions[0].ID != "proc-0" {
		t.Fatalf("sessions = %+v, want proc-0", d.Sessions)
	}
}
