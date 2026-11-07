package store

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Persistence does not wait for retention: the insert that starts a prune of
// an expired backlog returns while the prune is still held, and the backlog
// drains once it runs.
func TestRetentionDoesNotHoldTheInsertThatStartsIt(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	release := make(chan struct{})
	started := make(chan struct{})
	var hold sync.Once
	s.pruneScanned = func() {
		hold.Do(func() {
			close(started)
			<-release
		})
	}
	old := time.Now().Add(-60 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10000)
		INSERT INTO events (kind, ts, pid) SELECT ?, ?, 1 FROM n`, int(event.KindExec), old); err != nil {
		t.Fatal(err)
	}
	expired := func() int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE pid = 1`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	put := func() error {
		_, err := s.PutEvent(event.Event{Kind: event.KindExec, PID: 2, TS: time.Now()})
		return err
	}
	for i := 1; i < 1000; i++ {
		if err := put(); err != nil {
			t.Fatal(err)
		}
	}
	returned := make(chan error, 1)
	go func() { returned <- put() }() // the 1000th insert starts retention
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("the insert that started retention waited for it")
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("the 1000th insert did not start retention")
	}
	if n := expired(); n != 10000 {
		t.Fatalf("%d expired events before retention ran; want 10000", n)
	}
	close(release)
	s.retention.Wait()
	if n := expired(); n != 0 {
		t.Fatalf("%d expired events left after retention", n)
	}
}
