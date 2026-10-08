package store

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

func TestResourceEpisodeWriteFailureRecoversIndependently(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	s.PutEvent(event.Event{Kind: event.KindPluginAction, TS: time.Now()})
	episode := resource.Episode{CapturedAt: time.Now(), Session: resource.Session{Key: "saved"}}
	if err := s.PutResourceEpisode(episode); err == nil {
		t.Fatal("read-only database accepted an episode")
	}
	h := s.WriteHealth()
	if h.Failures != 2 || !slices.Equal(h.Active, []string{"events", "resource episodes"}) {
		t.Fatalf("resource write failure hidden: %+v", h)
	}
	if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	h = s.WriteHealth()
	if h.Failures != 2 || !slices.Equal(h.Active, []string{"events"}) {
		t.Fatalf("episode recovery changed unrelated evidence faults: %+v", h)
	}
	if got := s.RecentResourceEpisodes(1); len(got) != 1 || got[0].Session.Key != "saved" {
		t.Fatalf("recovered episode was not persisted: %+v", got)
	}
}

func TestResourceEpisodeMarshalFailureIsTracked(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	episode := resource.Episode{CapturedAt: time.Now(), Session: resource.Session{CPUPercent: math.Inf(1)}}
	if err := s.PutResourceEpisode(episode); err == nil {
		t.Fatal("invalid episode unexpectedly persisted")
	}
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"resource episodes"}) {
		t.Fatalf("pre-transaction persistence failure hidden: %+v", h)
	}
	if got := s.RecentResourceEpisodes(1); len(got) != 0 {
		t.Fatalf("invalid episode was stored: %+v", got)
	}
}

func TestResourceEpisodeEnrichmentWriteFailureRecoversIndependently(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	episode := resource.Episode{CapturedAt: time.Now().Add(-time.Hour), Session: resource.Session{Key: "saved"}}
	if err := s.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	got := s.RecentResourceEpisodes(1)
	if len(got) != 1 || got[0].ActivityStatus != "settling" {
		t.Fatalf("failed enrichment did not return the persisted fallback: %+v", got)
	}
	if err := s.PutResourceEpisode(episode); err == nil {
		t.Fatal("read-only database accepted an episode")
	}
	h := s.WriteHealth()
	if h.Failures != 2 || !slices.Equal(h.Active, []string{"resource episode enrichment", "resource episodes"}) {
		t.Fatalf("independent episode faults hidden: %+v", h)
	}
	if _, err := s.db.Exec("PRAGMA query_only = OFF"); err != nil {
		t.Fatal(err)
	}
	episode.CapturedAt = time.Now()
	if err := s.PutResourceEpisode(episode); err != nil {
		t.Fatal(err)
	}
	h = s.WriteHealth()
	if h.Failures != 2 || !slices.Equal(h.Active, []string{"resource episode enrichment"}) {
		t.Fatalf("new episode write cleared the failed enrichment: %+v", h)
	}
	got = s.RecentResourceEpisodes(1)
	if len(got) != 1 || got[0].ActivityStatus != "settling" {
		t.Fatalf("new episode unexpectedly settled: %+v", got)
	}
	h = s.WriteHealth()
	if h.Failures != 2 || !slices.Equal(h.Active, []string{"resource episode enrichment"}) {
		t.Fatalf("unchanged enrichment cleared the write fault: %+v", h)
	}
	got = s.RecentResourceEpisodes(2)
	if len(got) != 2 || got[0].ActivityStatus != "settling" || got[1].ActivityStatus != "complete" {
		t.Fatalf("enrichment did not recover: %+v", got)
	}
	h = s.WriteHealth()
	if h.Failures != 2 || len(h.Active) != 0 {
		t.Fatalf("enrichment recovery lost failure history or retained the fault: %+v", h)
	}
}

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
	s.PutGuardDecisionForTest(GuardDecision{ID: "g1", RuleID: "r1", At: now.Format(time.RFC3339Nano), Verdict: "deny"})
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
	s.PutGuardDecisionForTest(GuardDecision{ID: "g1", RuleID: "r1", At: now.Format(time.RFC3339Nano), Verdict: "deny"})
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
	if err := s.flagMirror.file.Close(); err != nil {
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

func TestFlagMirrorRotationFailureKeepsDatabaseAndRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "e.jsonl")
	s, err := Open(filepath.Join(dir, "e.db"), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.flagMirror.rotateBytes = 1
	s.PutFlag(model.Flag{ID: "before", TS: time.Now()})
	// A nonempty directory prevents replacing the retained mirror file.
	if err := os.Mkdir(path+".1", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".1", "obstruction"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.PutFlag(model.Flag{ID: "during", TS: time.Now()})
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"flag mirror"}) {
		t.Fatalf("rotation failure hidden: %+v", h)
	}
	if got := s.RecentFlags(10); len(got) != 2 {
		t.Fatalf("rotation failure stopped database writes: %+v", got)
	}
	assertMirrorIDs(t, path, "before")
	if err := os.RemoveAll(path + ".1"); err != nil {
		t.Fatal(err)
	}
	s.PutFlag(model.Flag{ID: "after", TS: time.Now()})
	h = s.WriteHealth()
	if h.Failures != 1 || len(h.Active) != 0 {
		t.Fatalf("rotation recovery erased evidence loss or retained the active fault: %+v", h)
	}
	assertMirrorIDs(t, path, "after")
	assertMirrorIDs(t, path+".1", "before")
	if got := s.RecentFlags(10); len(got) != 3 {
		t.Fatalf("database lost flags across mirror recovery: %+v", got)
	}
}

func TestFlagMirrorRotationFailurePreservesPreviousArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "e.jsonl")
	s, err := Open(filepath.Join(dir, "e.db"), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.flagMirror.rotateBytes = 1
	s.PutFlag(model.Flag{ID: "archived", TS: time.Now()})
	s.PutFlag(model.Flag{ID: "active", TS: time.Now()})
	prior, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	// Another process moves the active path while the mirror still holds its
	// descriptor. The next rotation must fail without deleting the archive.
	if err := os.Rename(path, path+".external"); err != nil {
		t.Fatal(err)
	}
	s.PutFlag(model.Flag{ID: "during", TS: time.Now()})
	h := s.WriteHealth()
	if h.Failures != 1 || !slices.Equal(h.Active, []string{"flag mirror"}) {
		t.Fatalf("rotation failure hidden: %+v", h)
	}
	retained, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("failed rotation lost the previous archive: %v", err)
	}
	if !bytes.Equal(retained, prior) {
		t.Fatal("failed rotation changed the previous archive")
	}
	assertMirrorIDs(t, path+".external", "active")
	if got := s.RecentFlags(10); len(got) != 3 {
		t.Fatalf("rotation failure stopped database writes: %+v", got)
	}
	s.PutFlag(model.Flag{ID: "after", TS: time.Now()})
	h = s.WriteHealth()
	if h.Failures != 1 || len(h.Active) != 0 {
		t.Fatalf("reopening did not clear only the active fault: %+v", h)
	}
	assertMirrorIDs(t, path, "after")
	assertMirrorIDs(t, path+".1", "archived")
	if got := s.RecentFlags(10); len(got) != 4 {
		t.Fatalf("database lost flags across recovery: %+v", got)
	}
}
