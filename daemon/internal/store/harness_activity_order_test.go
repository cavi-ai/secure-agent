package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestHarnessActivityOrdersFractionalSeconds(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	if err := s.UpsertSession(model.Session{ID: "s", Harness: "claude", StartedAt: base, LastSeenAt: base}); err != nil {
		t.Fatal(err)
	}
	s.PutEvent(event.Event{Kind: event.KindToolCall, SessionID: "s", TS: base, CallID: "a"})
	if got := s.HarnessActivitySince(base.Add(500 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("older event admitted: %v", got)
	}
	s.PutEvent(event.Event{Kind: event.KindToolCall, SessionID: "s", TS: base.Add(900 * time.Millisecond), CallID: "b"})
	if got := s.HarnessActivitySince(base.Add(-time.Second))["claude"].TraceLastSeen; got != "2026-10-08T12:00:00.9Z" {
		t.Fatalf("latest = %q", got)
	}
}
