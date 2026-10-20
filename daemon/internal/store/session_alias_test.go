package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func countEvents(t *testing.T, s *Store, where string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE ` + where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// An event resolved to a session before its rekey is written under the id
// its rows moved to; a session rekeyed back is live again.
func TestEventWritesFollowASessionRekey(t *testing.T) {
	s := rekeyFixture(t)
	if err := s.RekeySession("old", "new"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if _, err := s.PutEvent(event.Event{Kind: event.KindFileOpen, SessionID: "old", TS: now, Path: "/w/one"}); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, s, `session_id='old'`); n != 0 {
		t.Fatalf("%d rows under the rekeyed id", n)
	}
	if n := countEvents(t, s, `session_id='new' AND path='/w/one'`); n != 1 {
		t.Fatalf("%d rows under the new id, want 1", n)
	}

	if err := s.RekeySession("new", "old"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutEvent(event.Event{Kind: event.KindFileOpen, SessionID: "old", TS: now, Path: "/w/two"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutEvent(event.Event{Kind: event.KindFileOpen, SessionID: "new", TS: now, Path: "/w/three"}); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, s, `session_id='old' AND path IN ('/w/two','/w/three')`); n != 2 {
		t.Fatalf("%d rows under the id rekeyed back, want 2", n)
	}
}
