package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestEvidenceWriteHealthTracksIndependentFaultsAndRecovery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now})
	s.PutFlag(model.Flag{ID: "f1", TS: now})
	s.PutIncident(model.IncidentReport{ID: "i1", Timestamp: now})
	s.PutAudit(AuditEntry{Action: "dismiss"})
	s.UpsertSession(model.Session{ID: "s1", Harness: "claude", StartedAt: now, LastSeenAt: now})
	s.PutGuardDecision(GuardDecision{ID: "g1", RuleID: "r1", At: now.Format(time.RFC3339Nano), Verdict: "deny"})
	h := s.WriteHealth()
	want := []string{"events", "flags", "guard decisions", "incidents", "operator audit", "sessions"}
	if h.Failures != 6 || !slices.Equal(h.Active, want) {
		t.Fatalf("failed writes hidden: %+v", h)
	}
	if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
		t.Fatal(err)
	}
	s.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now})
	h = s.WriteHealth()
	if h.Failures != 6 || slices.Contains(h.Active, "events") || len(h.Active) != 5 {
		t.Fatalf("recovery erased unrelated faults or lost evidence: %+v", h)
	}
	s.PutFlag(model.Flag{ID: "f1", TS: now})
	s.PutIncident(model.IncidentReport{ID: "i1", Timestamp: now})
	s.PutAudit(AuditEntry{Action: "dismiss"})
	s.UpsertSession(model.Session{ID: "s1", Harness: "claude", StartedAt: now, LastSeenAt: now})
	s.PutGuardDecision(GuardDecision{ID: "g1", RuleID: "r1", At: now.Format(time.RFC3339Nano), Verdict: "deny"})
	h = s.WriteHealth()
	if h.Failures != 6 || len(h.Active) != 0 {
		t.Fatalf("writes did not recover independently: %+v", h)
	}
}

func TestFlagMirrorFailureRecoversOnNextWrite(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.jsonlFile.Close(); err != nil {
		t.Fatal(err)
	}
	s.PutFlag(model.Flag{ID: "f1", TS: time.Now()})
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"flag mirror"}) {
		t.Fatalf("mirror failure hidden: %+v", h)
	}
	s.PutFlag(model.Flag{ID: "f2", TS: time.Now()})
	h = s.WriteHealth()
	if h.Failures != 1 || len(h.Active) != 0 {
		t.Fatalf("mirror did not reopen: %+v", h)
	}
	if got := s.RecentFlags(10); len(got) != 2 {
		t.Fatalf("mirror fault stopped database writes: %+v", got)
	}
}

func TestConfiguredFlagMirrorUnavailableAtStartup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), dir) // directory cannot be an append-only file
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"flag mirror"}) {
		t.Fatalf("missing configured mirror reported healthy: %+v", h)
	}
}
