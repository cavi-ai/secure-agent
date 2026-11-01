package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/internal/hookhealth"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestHookHealthRoundTripAttributionAndRecovery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		e := hookRun("s", fmt.Sprint(i), "PreToolUse", "same.py", "error", 0, 0, now.Add(time.Duration(i-5)*time.Second))
		e.HookHarness = "hermes"
		e.HookEvidence = &hookrun.Evidence{HandlerID: "first", ConfigID: "c", DurationKnown: true}
		if _, err := s.PutEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	e := hookRun("s", "other", "PreToolUse", "same.py", "cancelled", 0, 0, now.Add(-time.Second))
	e.HookHarness = "hermes"
	e.HookEvidence = &hookrun.Evidence{HandlerID: "second"}
	if _, err := s.PutEvent(e); err != nil {
		t.Fatal(err)
	}
	rows, err := s.SessionHooks("s")
	if err != nil || len(rows) != 2 || rows[0].Errors != 3 || rows[0].Cancelled != 0 || rows[0].DurationSamples != 3 || rows[1].Cancelled != 1 || rows[1].Errors != 0 {
		t.Fatalf("identity/cancellation/zero: %+v %v", rows, err)
	}
	a, err := s.SessionHookHealth("s", now)
	if err != nil || len(a.Findings) != 1 || a.Findings[0].Count != 3 {
		t.Fatalf("health = %+v %v", a, err)
	}
	e.CallID = "recovery"
	e.ToolStatus = "ok"
	e.HookEvidence.HandlerID = "first"
	e.HookEvidence.ConfigID = "c"
	e.TS = now
	if _, err := s.PutEvent(e); err != nil {
		t.Fatal(err)
	}
	a, err = s.SessionHookHealth("s", now)
	if err != nil || len(a.Findings) != 0 {
		t.Fatalf("recovery = %+v %v", a, err)
	}
	if _, err := s.db.Exec(`ALTER TABLE hook_runs RENAME TO unavailable_hooks`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SessionHookHealth("s", now); err == nil {
		t.Fatal("read error became empty health")
	}
}

func TestHookHealthBoundedAndFutureExcluded(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	for i := 0; i < hookhealth.RunLimit+2; i++ {
		e := hookRun("s", fmt.Sprint(i), "Stop", "same.py", "ok", 0, 0, now.Add(-time.Second).Add(time.Duration(i)*time.Nanosecond))
		if _, err := s.PutEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PutEvent(hookRun("s", "future", "Stop", "same.py", "error", 0, 0, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	a, err := s.SessionHookHealth("s", now)
	if err != nil || !a.Truncated || a.ObservedRuns != hookhealth.RunLimit || a.UnattributedRuns != hookhealth.RunLimit {
		t.Fatalf("unbounded or invented attribution: %+v %v", a, err)
	}
}

func TestHookHealthNeverSplitsAnAmbiguousTimestampAtLimit(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	for i := 0; i < hookhealth.RunLimit+1; i++ {
		e := hookRun("s", fmt.Sprintf("%04d", i), "Stop", "same.py", "error", 0, 0, now)
		e.HookHarness = "hermes"
		e.HookEvidence = &hookrun.Evidence{HandlerID: "h"}
		if i == 0 {
			e.ToolStatus = "ok"
		}
		if _, err := s.PutEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.SessionHookHealth("s", now)
	if err != nil || !a.Truncated || len(a.Findings) != 0 {
		t.Fatalf("omitted tied success caused false diagnosis: %+v %v", a, err)
	}
}

func TestHookMetadataMigrationPreservesLegacyUnknowns(t *testing.T) {
	path := migrationFixture(t, `CREATE TABLE hook_runs (id INTEGER PRIMARY KEY AUTOINCREMENT,session_id TEXT NOT NULL,run_id TEXT NOT NULL,ts TEXT NOT NULL,hook TEXT NOT NULL,script TEXT NOT NULL,status TEXT NOT NULL,duration_ms INTEGER NOT NULL DEFAULT 0,chars INTEGER NOT NULL DEFAULT 0,UNIQUE(session_id,run_id));
	INSERT INTO hook_runs(session_id,run_id,ts,hook,script,status) VALUES ('s','old','2026-10-13T10:00:00Z','Stop','same.py','cancelled');`)
	for range 2 {
		s, err := Open(path, "")
		if err != nil {
			t.Fatal(err)
		}
		rows, err := s.SessionHooks("s")
		if err != nil || len(rows) != 1 || rows[0].Cancelled != 1 || rows[0].Errors != 0 || rows[0].DurationSamples != 0 || rows[0].CharSamples != 0 || rows[0].HandlerID != "" {
			t.Fatalf("legacy facts changed: %+v %v", rows, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// A session that logs more runs than one read holds does not hide another
// live session's failing hook.
func TestActiveHookFindingsPerSession(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	for _, id := range []string{"busy", "quiet"} {
		if err := s.UpsertSession(model.Session{ID: id, StartedAt: now.Add(-time.Hour), LastSeenAt: now, Status: model.SessionActive, Confidence: model.ConfHook}); err != nil {
			t.Fatal(err)
		}
	}
	put := func(session, id, status string, at time.Time) {
		e := hookRun(session, id, "PreToolUse", "guard.py", status, 0, 0, at)
		e.HookHarness = "claude"
		e.HookEvidence = &hookrun.Evidence{HandlerID: "guard", ConfigID: "c"}
		if _, err := s.PutEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		put("quiet", fmt.Sprint("q", i), "error", now.Add(-10*time.Minute+time.Duration(i)*time.Second))
	}
	for i := 0; i <= hookhealth.RunLimit; i++ {
		put("busy", fmt.Sprint("b", i), "ok", now.Add(-5*time.Minute+time.Duration(i)*100*time.Millisecond))
	}
	findings, _, err := s.ActiveHookFindings(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.SessionID == "quiet" {
			return
		}
	}
	t.Fatalf("quiet session's failing hook hidden: %+v", findings)
}
