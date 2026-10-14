package store

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func hookRun(session, id, hook, script, status string, ms, chars int64, at time.Time) event.Event {
	return event.Event{Kind: event.KindHookRun, TS: at, SessionID: session, CallID: id,
		ToolName: hook, Detail: script, ToolStatus: status, DurationMs: ms, Chars: chars}
}

func TestSessionHooksSummarizesRunsPerHook(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now().UTC().Truncate(time.Second)
	runs := []event.Event{
		hookRun("sess-1", "r1", "PreToolUse:Bash", "secret_guard.py", "ok", 30, 0, at),
		hookRun("sess-1", "r2", "PreToolUse:Edit", "secret_guard.py", "error", 40, 0, at.Add(time.Second)),
		hookRun("sess-1", "r3", "UserPromptSubmit", "user-prompt-hook.sh", "inject", 16, 11, at),
		hookRun("sess-1", "block:t9", "PreToolUse:Bash", "", "block", 0, 9, at),
		hookRun("sess-2", "r1", "PreToolUse:Bash", "secret_guard.py", "ok", 30, 0, at),
	}
	for _, r := range runs {
		if w, err := s.PutEvent(r); err != nil || !w.Changed {
			t.Fatalf("put %s: %+v %v", r.CallID, w, err)
		}
	}
	// A transcript re-read replays the same record: no second row.
	if w, err := s.PutEvent(runs[0]); err != nil || w.Changed {
		t.Fatalf("replayed run changed the store: %+v %v", w, err)
	}
	got, err := s.SessionHooks("sess-1")
	if err != nil {
		t.Fatal(err)
	}
	last := at.Add(time.Second).Format("2006-01-02T15:04:05") + ".000000000Z"
	first := at.Format("2006-01-02T15:04:05") + ".000000000Z"
	want := []HookSummary{
		{Event: "PreToolUse", Script: "secret_guard.py", Runs: 2, Errors: 1, TotalMs: 70, DurationSamples: 2, LastAt: last},
		{Event: "PreToolUse", Script: "", Runs: 1, Blocks: 1, Chars: 9, CharSamples: 1, LastAt: first},
		{Event: "UserPromptSubmit", Script: "user-prompt-hook.sh", Runs: 1, Chars: 11, TotalMs: 16, DurationSamples: 1, CharSamples: 1, LastAt: first},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary =\n%+v\nwant\n%+v", got, want)
	}
	// Hook runs never land in the events table the timelines read.
	evs, err := s.QueryEvents(EventFilter{SessionID: "sess-1", Limit: 100})
	if err != nil || len(evs) != 0 {
		t.Fatalf("events for session = %d %v, want none", len(evs), err)
	}
}

func TestPruneBoundsHookRuns(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	prev := hookRunBudget
	hookRunBudget = 2
	defer func() { hookRunBudget = prev }()
	now := time.Now().UTC()
	for i, at := range []time.Time{now.AddDate(-1, 0, 0), now.Add(-3 * time.Second), now.Add(-2 * time.Second), now.Add(-time.Second)} {
		if _, err := s.PutEvent(hookRun("sess-1", string(rune('a'+i)), "Stop", "stop.py", "ok", 1, 0, at)); err != nil {
			t.Fatal(err)
		}
	}
	s.PruneEvents()
	got, err := s.SessionHooks("sess-1")
	if err != nil || len(got) != 1 || got[0].Runs != 2 {
		t.Fatalf("after prune = %+v %v, want the newest 2 runs", got, err)
	}
}

func TestRekeyPreservesHookRuns(t *testing.T) {
	s := rekeyFixture(t)
	at := time.Now().UTC()
	for _, run := range []event.Event{
		hookRun("old", "unique", "Stop", "stop.py", "ok", 5, 0, at),
		hookRun("old", "duplicate", "Stop", "stop.py", "error", 9, 0, at),
		hookRun("new", "duplicate", "Stop", "stop.py", "inject", 7, 4, at),
	} {
		if _, err := s.PutEvent(run); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_hook_rekey BEFORE UPDATE ON hook_runs BEGIN SELECT RAISE(ABORT,'injected rekey failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RekeySession("old", "new"); err == nil {
		t.Fatal("hook update failure did not reject the rekey")
	}
	old, err := s.SessionHooks("old")
	if err != nil || len(old) != 1 || old[0].Runs != 2 {
		t.Fatalf("rollback lost old hook runs: %+v %v", old, err)
	}
	if _, found, err := s.GetSession("old"); err != nil || !found {
		t.Fatalf("rollback lost the old session: %v %v", found, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_hook_rekey`); err != nil {
		t.Fatal(err)
	}
	if err := s.RekeySession("old", "new"); err != nil {
		t.Fatal(err)
	}
	old, err = s.SessionHooks("old")
	if err != nil || len(old) != 0 {
		t.Fatalf("orphan hook runs: %+v %v", old, err)
	}
	got, err := s.SessionHooks("new")
	if err != nil || len(got) != 1 || got[0].Runs != 2 || got[0].Errors != 0 || got[0].TotalMs != 12 || got[0].Chars != 4 {
		t.Fatalf("rekey did not retain unique and canonical runs: %+v %v", got, err)
	}
}
