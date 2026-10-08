package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestEgressEpisodeRecurrenceAndScope(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	scope := EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
	for i := 0; i < 5; i++ {
		if err := s.RecordEgressObservationForTest(EgressObservation{Scope: scope, SessionID: "one", Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: base.Add(time.Duration(i) * 30 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordEgressObservationForTest(EgressObservation{Scope: scope, SessionID: "burst", Host: "203.0.113.2", Protocol: "tcp", Port: 443, At: base.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	rows := s.ListEgressEpisodes(10)
	if len(rows) != 2 {
		t.Fatalf("episodes=%+v", rows)
	}
	var spaced, burst EgressEpisode
	for _, row := range rows {
		if row.Host == "203.0.113.1" {
			spaced = row
		} else {
			burst = row
		}
	}
	if !spaced.Recurring || spaced.Count != 5 || len(spaced.Intervals) != 4 || !spaced.ScopeComplete {
		t.Fatalf("spaced=%+v", spaced)
	}
	if burst.Recurring || burst.Count != 5 {
		t.Fatalf("burst=%+v", burst)
	}
	if err := s.RecordEgressObservationForTest(EgressObservation{Scope: scope, SessionID: "two", Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: base.Add(5 * 30 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	rows = s.ListEgressEpisodes(10)
	for _, row := range rows {
		if row.ID == spaced.ID && (row.Count != 6 || len(row.SessionIDs) != 2) {
			t.Fatalf("continued=%+v", row)
		}
	}
	if err := s.RecordEgressObservationForTest(EgressObservation{Scope: EgressScope{Agent: "claude"}, Host: "203.0.113.3", Protocol: "tcp", Port: 443, At: base}); err != nil {
		t.Fatal(err)
	}
	for _, row := range s.ListEgressEpisodes(10) {
		if row.Host == "203.0.113.3" && row.ScopeComplete {
			t.Fatalf("incomplete scope marked complete: %+v", row)
		}
	}
}

func TestEgressEpisodePersistenceAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "episodes.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	scope := EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
	for i := 0; i < 30; i++ {
		if err := s.RecordEgressObservationForTest(EgressObservation{Scope: scope, SessionID: "s" + string(rune('a'+i)), Host: "example.org", Protocol: "tcp", Port: 443, At: base.Add(time.Duration(i) * 30 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows := s.ListEgressEpisodes(10)
	if len(rows) != 1 || rows[0].Count != 30 || len(rows[0].Intervals) > 16 || len(rows[0].SessionIDs) > 8 {
		t.Fatalf("bounds/persistence=%+v", rows)
	}
	if len(s.ListEgressEpisodes(10000)) > 500 {
		t.Fatal("query cap not enforced")
	}
}

func TestEgressEpisodeRetentionAndStorageCap(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxEgressEpisodes+4; i++ {
		at := now.Add(-time.Duration(maxEgressEpisodes+4-i) * time.Second).UnixNano()
		_, err := tx.Exec(`INSERT INTO egress_episodes(id,agent,exe_path,harness,workspace,host,protocol,port,count,first_seen_ns,last_seen_ns,intervals_json,session_ids_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, fmt.Sprintf("seed-%04d", i), "agent", "", "", "", "example.org", "tcp", 443, 1, at, at, "[]", "[]")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordEgressObservationForTest(EgressObservation{Scope: EgressScope{Agent: "agent"}, Host: "new.example", Protocol: "tcp", Port: 443, At: now}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM egress_episodes`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != maxEgressEpisodes {
		t.Fatalf("row cap=%d", count)
	}
	var oldest int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM egress_episodes WHERE id='seed-0000'`).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	if oldest != 0 {
		t.Fatal("oldest row was not evicted")
	}
	if _, err := s.db.Exec(`UPDATE egress_episodes SET last_seen_ns=?`, now.Add(-8*24*time.Hour).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if got := s.ListEgressEpisodes(10); len(got) != 0 {
		t.Fatalf("expired rows visible: %+v", got)
	}
}

// The projection reads, then writes, while the drain loop writes events on
// other connections. A deferred transaction failed that upgrade at once with
// SQLITE_BUSY or SQLITE_BUSY_SNAPSHOT and the observation was dropped. With no
// deadline, every failure is a lock failure.
func TestEgressObservationSurvivesConcurrentWriters(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	stop := make(chan struct{})
	writers := make(chan struct{})
	for w := 0; w < 4; w++ {
		go func() {
			defer func() { writers <- struct{}{} }()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				s.PutEvent(event.Event{Kind: event.KindConnOpen, PID: int32(w), TS: time.Now(), RemoteHost: "x.example.com", RemotePort: 443})
			}
		}()
	}
	base := time.Now()
	const n = 200
	var locked []error
	for i := 0; i < n; i++ {
		o := EgressObservation{Scope: EgressScope{Agent: "codex"}, Host: "api.example.com", Protocol: "tcp", Port: 443, At: base.Add(time.Duration(i) * time.Second)}
		if err := s.RecordEgressObservationForTest(o); err != nil {
			locked = append(locked, err)
		}
	}
	close(stop)
	for w := 0; w < 4; w++ {
		<-writers
	}
	if len(locked) > 0 {
		t.Fatalf("%d of %d observations failed on a lock beside concurrent writers; first: %v", len(locked), n, locked[0])
	}
	eps := s.ListEgressEpisodes(10)
	if len(eps) != 1 || eps[0].Count != n {
		t.Fatalf("episodes = %+v, want one with count %d", eps, n)
	}
}

// Production keeps its best-effort bound; the fixture path waits out a stall.
func TestEgressObservationDeadlineIsProductionOnly(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	o := EgressObservation{Scope: EgressScope{Agent: "codex"}, Host: "api.example.com", Protocol: "tcp", Port: 443, At: time.Now()}
	stall := func(record func(EgressObservation) error) error {
		s.egressMu.Lock()
		go func() {
			time.Sleep(300 * time.Millisecond)
			s.egressMu.Unlock()
		}()
		return record(o)
	}
	if err := stall(s.RecordEgressObservation); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("production write behind a 300 ms stall = %v, want context.DeadlineExceeded", err)
	}
	if err := stall(s.RecordEgressObservationForTest); err != nil {
		t.Fatalf("fixture write behind a 300 ms stall = %v, want nil", err)
	}
	if eps := s.ListEgressEpisodes(10); len(eps) != 1 || eps[0].Count != 1 {
		t.Fatalf("episodes = %+v, want one with count 1", eps)
	}
}

func TestListRecurringEgressEpisodesReturnsOnlyRecurring(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	scope := EgressScope{Agent: "claude", ExePath: "/usr/bin/claude", Harness: "claude", Workspace: "/work/a"}
	record := func(host string, n int, gap time.Duration, offset time.Duration) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := s.RecordEgressObservationForTest(EgressObservation{Scope: scope, Host: host, Protocol: "tcp", Port: 443, At: base.Add(offset + time.Duration(i)*gap)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	record("203.0.113.1", 5, 30*time.Minute, 0)         // recurring
	record("203.0.113.2", 5, time.Second, 0)            // a burst
	record("203.0.113.3", 4, 30*time.Minute, 0)         // too few calls
	record("203.0.113.4", 6, 20*time.Minute, time.Hour) // recurring, newer
	if all := s.ListEgressEpisodesForReview(); len(all) != 4 {
		t.Fatalf("review list = %d episodes, want 4", len(all))
	}
	got := s.ListRecurringEgressEpisodes()
	if len(got) != 2 || got[0].Host != "203.0.113.4" || got[1].Host != "203.0.113.1" {
		t.Fatalf("recurring = %+v, want 203.0.113.4 then 203.0.113.1", got)
	}
	for _, e := range got {
		if !e.Recurring {
			t.Fatalf("non-recurring episode listed: %+v", e)
		}
	}
}
