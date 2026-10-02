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
		if err := s.RecordEgressObservation(EgressObservation{Scope: scope, SessionID: "one", Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: base.Add(time.Duration(i) * 30 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordEgressObservation(EgressObservation{Scope: scope, SessionID: "burst", Host: "203.0.113.2", Protocol: "tcp", Port: 443, At: base.Add(time.Duration(i) * time.Second)}); err != nil {
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
	if err := s.RecordEgressObservation(EgressObservation{Scope: scope, SessionID: "two", Host: "203.0.113.1", Protocol: "tcp", Port: 443, At: base.Add(5 * 30 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	rows = s.ListEgressEpisodes(10)
	for _, row := range rows {
		if row.ID == spaced.ID && (row.Count != 6 || len(row.SessionIDs) != 2) {
			t.Fatalf("continued=%+v", row)
		}
	}
	if err := s.RecordEgressObservation(EgressObservation{Scope: EgressScope{Agent: "claude"}, Host: "203.0.113.3", Protocol: "tcp", Port: 443, At: base}); err != nil {
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
		if err := s.RecordEgressObservation(EgressObservation{Scope: scope, SessionID: "s" + string(rune('a'+i)), Host: "example.org", Protocol: "tcp", Port: 443, At: base.Add(time.Duration(i) * 30 * time.Minute)}); err != nil {
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
	if err := s.RecordEgressObservation(EgressObservation{Scope: EgressScope{Agent: "agent"}, Host: "new.example", Protocol: "tcp", Port: 443, At: now}); err != nil {
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
// SQLITE_BUSY or SQLITE_BUSY_SNAPSHOT and the observation was dropped. The
// 75 ms bound may still drop one on a starved machine; a lock failure may not.
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
	recorded := 0
	var locked []error
	for i := 0; i < n; i++ {
		o := EgressObservation{Scope: EgressScope{Agent: "codex"}, Host: "api.example.com", Protocol: "tcp", Port: 443, At: base.Add(time.Duration(i) * time.Second)}
		switch err := s.RecordEgressObservation(o); {
		case err == nil:
			recorded++
		case !errors.Is(err, context.DeadlineExceeded):
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
	if recorded < n/2 {
		t.Fatalf("only %d of %d observations recorded", recorded, n)
	}
	eps := s.ListEgressEpisodes(10)
	if len(eps) != 1 || eps[0].Count != recorded {
		t.Fatalf("episodes = %+v, want one with count %d", eps, recorded)
	}
}
