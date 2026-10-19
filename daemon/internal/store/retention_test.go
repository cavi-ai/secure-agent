package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Persistence does not wait for retention: the insert that starts a prune of
// an expired backlog costs what its neighbours cost, and the backlog still
// drains.
func TestRetentionDoesNotHoldTheInsertThatStartsIt(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := time.Now().Add(-60 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10000)
		INSERT INTO events (kind, ts, pid) SELECT ?, ?, 1 FROM n`, int(event.KindExec), old); err != nil {
		t.Fatal(err)
	}
	put := func() time.Duration {
		start := time.Now()
		if _, err := s.PutEvent(event.Event{Kind: event.KindExec, PID: 2, TS: time.Now()}); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	var slowest time.Duration
	for i := 1; i < 1000; i++ {
		if d := put(); i > 900 && d > slowest {
			slowest = d
		}
	}
	if held := put(); held > max(10*slowest, 25*time.Millisecond) { // the 1000th insert starts retention
		t.Fatalf("the insert that started retention took %v; its neighbours took at most %v", held, slowest)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		var expired int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE pid = 1`).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d expired events left after retention", expired)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
