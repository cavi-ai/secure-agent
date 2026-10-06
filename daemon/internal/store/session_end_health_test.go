package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestEndSessionFailureIsAtomicAndRecovers(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	kind := int(event.KindToolCall)
	s.UpsertSession(model.Session{ID: "session", Status: model.SessionActive, StartedAt: now, LastSeenAt: now})
	s.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "session", CallID: "call", ToolName: "Read", ToolStatus: "running"})
	if _, err := s.db.Exec(`CREATE TRIGGER fail_call_close BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'injected call-close failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.EndSession("session", now.Add(time.Minute)); err == nil {
		t.Fatal("failed session ending reported success")
	}
	if saved, ok := s.GetSession("session"); !ok || saved.Status != model.SessionActive || saved.EndedAt != nil || !saved.LastSeenAt.Equal(now) {
		t.Fatalf("failed ending partially changed the session: %+v, %v", saved, ok)
	}
	if calls := s.QueryEvents(EventFilter{Kind: &kind}); len(calls) != 1 || calls[0].ToolStatus != "running" {
		t.Fatalf("failed ending changed the running call: %+v", calls)
	}
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"session endings"}) {
		t.Fatalf("session ending failure hidden: %+v", h)
	}
	// A successful upsert is a different operation and cannot recover the
	// failed session/tool-call transition.
	s.UpsertSession(model.Session{ID: "other", StartedAt: now, LastSeenAt: now})
	h = s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"session endings"}) {
		t.Fatalf("upsert cleared an ending failure: %+v", h)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_call_close"); err != nil {
		t.Fatal(err)
	}
	if err := s.EndSession("missing", now); err != nil {
		t.Fatal(err)
	}
	h = s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"session endings"}) {
		t.Fatalf("missing session cleared an ending failure: %+v", h)
	}
	if err := s.EndSession("session", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if saved, ok := s.GetSession("session"); !ok || saved.Status != model.SessionEnded || saved.EndedAt == nil || !saved.EndedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("ending did not recover: %+v, %v", saved, ok)
	}
	if calls := s.QueryEvents(EventFilter{Kind: &kind}); len(calls) != 1 || calls[0].ToolStatus != "error" {
		t.Fatalf("recovered ending did not close the running call: %+v", calls)
	}
	h = s.WriteHealth()
	if h.Failures != 1 || len(h.Active) != 0 {
		t.Fatalf("ending recovery lost history or retained fault: %+v", h)
	}
}
