package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestEventWriteResultRejectsIgnoredNewRows(t *testing.T) {
	for _, e := range []event.Event{
		{Kind: event.KindConnOpen},
		{Kind: event.KindModelCall, CallID: "model"},
		{Kind: event.KindToolCall, CallID: "tool"},
		{Kind: event.KindTurn},
	} {
		t.Run(e.Kind.String(), func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			e.SessionID, e.TS = "session", time.Now().UTC()
			if _, err := s.db.Exec(`CREATE TRIGGER ignore_event BEFORE INSERT ON events BEGIN SELECT RAISE(IGNORE); END`); err != nil {
				t.Fatal(err)
			}
			result, err := s.PutEvent(e)
			if err == nil || result.Changed || !result.HealthChanged || len(s.RecentEvents(10)) != 0 {
				t.Fatalf("ignored insert reported success: %+v, %v", result, err)
			}
			if _, err := s.db.Exec("DROP TRIGGER ignore_event"); err != nil {
				t.Fatal(err)
			}
			result, err = s.PutEvent(e)
			if err != nil || !result.Changed || !result.HealthChanged || len(s.RecentEvents(10)) != 1 {
				t.Fatalf("insert did not recover: %+v, %v", result, err)
			}
			if h := s.WriteHealth(); h.Failures != 1 || len(h.Active) != 0 {
				t.Fatalf("recovery erased history: %+v", h)
			}
		})
	}
}

func TestEventDuplicateDoesNotClearOutstandingWriteFault(t *testing.T) {
	for _, kind := range []event.Kind{event.KindModelCall, event.KindTurn} {
		t.Run(kind.String(), func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			e := event.Event{Kind: kind, TS: time.Now().UTC(), SessionID: "session", TokensIn: 100}
			if kind == event.KindModelCall {
				e.CallID = "model"
			}
			if result, err := s.PutEvent(e); err != nil || !result.Changed || result.HealthChanged {
				t.Fatalf("healthy insert result: %+v, %v", result, err)
			}
			if _, err := s.db.Exec(`CREATE TRIGGER reject_connection BEFORE INSERT ON events WHEN NEW.kind=5 BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.PutEvent(event.Event{Kind: event.KindConnOpen, TS: e.TS}); err == nil {
				t.Fatal("injected failure was hidden")
			}
			result, err := s.PutEvent(e)
			if err != nil || result.Changed || result.HealthChanged {
				t.Fatalf("stored duplicate result: %+v, %v", result, err)
			}
			if h := s.WriteHealth(); h.Failures != 1 || len(h.Active) != 1 || h.Active[0] != "events" {
				t.Fatalf("duplicate cleared failed-write health: %+v", h)
			}
		})
	}
}

func TestModelWriteResultRejectsIgnoredUsageIncrease(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := event.Event{Kind: event.KindModelCall, TS: time.Now().UTC(), SessionID: "session", CallID: "model", TokensIn: 100}
	if _, err := s.PutEvent(e); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER ignore_usage BEFORE UPDATE ON events BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	e.TokensIn = 200
	if result, err := s.PutEvent(e); err == nil || result.Changed || !result.HealthChanged {
		t.Fatalf("ignored usage increase was mistaken for a duplicate: %+v, %v", result, err)
	}
	if got := s.RecentEvents(10); len(got) != 1 || got[0].TokensIn != 100 {
		t.Fatalf("rejected usage changed saved row: %+v", got)
	}
	if _, err := s.db.Exec("DROP TRIGGER ignore_usage"); err != nil {
		t.Fatal(err)
	}
	if result, err := s.PutEvent(e); err != nil || !result.Changed || !result.HealthChanged {
		t.Fatalf("usage increase did not recover: %+v, %v", result, err)
	}
}

func TestFlagWriteResultKeepsMirrorConsistentWithSQLite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flags.jsonl")
	s, err := Open(filepath.Join(dir, "events.db"), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`CREATE TRIGGER reject_flag BEFORE INSERT ON flags BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	flag := model.Flag{ID: "flag", TS: time.Now().UTC()}
	if result, err := s.PutFlag(flag); err == nil || result.Changed || !result.HealthChanged {
		t.Fatalf("rejected flag result: %+v, %v", result, err)
	}
	assertMirrorIDs(t, path)
	if _, err := s.db.Exec("DROP TRIGGER reject_flag"); err != nil {
		t.Fatal(err)
	}
	if err := s.flagMirror.file.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := s.PutFlag(flag)
	if err != nil || !result.Changed || !result.HealthChanged {
		t.Fatalf("mirror failure invalidated saved flag: %+v, %v", result, err)
	}
	if _, ok := s.GetFlag(flag.ID); !ok {
		t.Fatal("mirror failure lost saved flag")
	}
	if h := s.WriteHealth(); h.Failures != 2 || len(h.Active) != 1 || h.Active[0] != "flag mirror" {
		t.Fatalf("mirror health was conflated with SQLite outcome: %+v", h)
	}
	flag.ID = "recovered"
	if result, err := s.PutFlag(flag); err != nil || !result.Changed || !result.HealthChanged {
		t.Fatalf("mirror did not recover: %+v, %v", result, err)
	}
	assertMirrorIDs(t, path, "recovered")
}
