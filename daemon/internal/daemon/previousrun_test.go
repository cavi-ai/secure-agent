package daemon

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

var testBoot = time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)

type runClock struct{ t time.Time }

func (c *runClock) now() time.Time { return c.t }

func bootAt(at time.Time) func() (time.Time, error) {
	return func() (time.Time, error) { return at, nil }
}

// openRunStore opens a store under a temp dir and returns it with the run
// record path the daemon uses for that database.
func openRunStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "events.db")
	st, err := store.Open(dbPath, filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, dbPath + runRecordSuffix
}

func monitorStoppedFlags(t *testing.T, st *store.Store) []model.Flag {
	t.Helper()
	flags, err := st.QueryFlags(store.FlagFilter{Rule: monitorStoppedRule, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	return flags
}

// endedRun records one run that started at start and ended with cause at end.
func endedRun(t *testing.T, path string, clock *runClock, pid int, start, end time.Time, cause RunEnding) {
	t.Helper()
	clock.t = start
	run, err := StartRun(path, pid, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	clock.t = end
	if _, err := run.Stop(cause); err != nil {
		t.Fatal(err)
	}
}

// startNext starts the next run at a time after every recorded run.
func startNext(t *testing.T, path string, clock *runClock) *RunTracker {
	t.Helper()
	clock.t = testBoot.Add(3 * time.Hour)
	run, err := StartRun(path, 5151, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func requireOneFinding(t *testing.T, st *store.Store, want ...string) model.Flag {
	t.Helper()
	flags := monitorStoppedFlags(t, st)
	if len(flags) != 1 {
		t.Fatalf("stored %d %s findings, want 1: %+v", len(flags), monitorStoppedRule, flags)
	}
	f := flags[0]
	if f.Severity != 3 || len(f.Evidence) != 1 {
		t.Fatalf("finding = %+v, want severity 3 with one evidence item", f)
	}
	for _, w := range want {
		if !strings.Contains(f.Evidence[0].Text, w) {
			t.Errorf("finding text %q does not contain %q", f.Evidence[0].Text, w)
		}
	}
	return f
}

func TestPreviousRunSignalSameBootRaisesFinding(t *testing.T) {
	st, path := openRunStore(t)
	clock := &runClock{}
	start, end := testBoot.Add(time.Hour), testBoot.Add(2*time.Hour)
	endedRun(t, path, clock, 4242, start, end, RunEndingSignal)

	raisePreviousRunFindings(st, startNext(t, path, clock), bootAt(testBoot), clock.now)

	requireOneFinding(t, st, "pid 4242", "signal with no stop intent", start.Format(time.RFC3339), end.Format(time.RFC3339))
}

func TestPreviousRunParentExitSameBootRaisesFinding(t *testing.T) {
	st, path := openRunStore(t)
	clock := &runClock{}
	start, end := testBoot.Add(time.Hour), testBoot.Add(2*time.Hour)
	endedRun(t, path, clock, 4242, start, end, RunEndingParentExit)

	raisePreviousRunFindings(st, startNext(t, path, clock), bootAt(testBoot), clock.now)

	requireOneFinding(t, st, "pid 4242", "owning app process exited", start.Format(time.RFC3339), end.Format(time.RFC3339))
}

func TestPreviousRunWithoutEndingRaisesFinding(t *testing.T) {
	st, path := openRunStore(t)
	clock := &runClock{t: testBoot.Add(time.Hour)}
	if _, err := StartRun(path, 4242, clock.now); err != nil {
		t.Fatal(err)
	}

	raisePreviousRunFindings(st, startNext(t, path, clock), bootAt(testBoot), clock.now)

	requireOneFinding(t, st, "pid 4242", "no ending recorded", testBoot.Add(time.Hour).Format(time.RFC3339))
}

func TestPreviousRunOwnerStopRaisesNothing(t *testing.T) {
	st, path := openRunStore(t)
	clock := &runClock{t: testBoot.Add(time.Hour)}
	run, err := StartRun(path, 4242, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := run.RecordStopIntent(); err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(time.Second)
	if ending, err := run.Stop(RunEndingSignal); err != nil || ending != RunEndingOwnerStop {
		t.Fatalf("Stop = %s, %v; want %s", ending, err, RunEndingOwnerStop)
	}

	raisePreviousRunFindings(st, startNext(t, path, clock), bootAt(testBoot), clock.now)

	if flags := monitorStoppedFlags(t, st); len(flags) != 0 {
		t.Fatalf("owner stop stored findings: %+v", flags)
	}
}

func TestPreviousRunBeforeBootRaisesNothing(t *testing.T) {
	for _, cause := range []RunEnding{RunEndingSignal, RunEndingParentExit, RunEndingAPIFailure, RunEndingStartFailure, RunEndingNoRecord} {
		t.Run(string(cause), func(t *testing.T) {
			st, path := openRunStore(t)
			clock := &runClock{}
			start := testBoot.Add(-2 * time.Hour)
			if cause == RunEndingNoRecord {
				clock.t = start
				if _, err := StartRun(path, 4242, clock.now); err != nil {
					t.Fatal(err)
				}
			} else {
				endedRun(t, path, clock, 4242, start, testBoot.Add(-time.Minute), cause)
			}

			raisePreviousRunFindings(st, startNext(t, path, clock), bootAt(testBoot), clock.now)

			if flags := monitorStoppedFlags(t, st); len(flags) != 0 {
				t.Fatalf("run before boot stored findings: %+v", flags)
			}
		})
	}
}

func TestPreviousRunNoRecordRaisesNothing(t *testing.T) {
	st, path := openRunStore(t)
	clock := &runClock{}

	raisePreviousRunFindings(st, startNext(t, path, clock), bootAt(testBoot), clock.now)

	if flags := monitorStoppedFlags(t, st); len(flags) != 0 {
		t.Fatalf("first run stored findings: %+v", flags)
	}
}

func TestPreviousRunUnreadableBootTimeRaisesFinding(t *testing.T) {
	st, path := openRunStore(t)
	clock := &runClock{}
	start, end := testBoot.Add(time.Hour), testBoot.Add(2*time.Hour)
	endedRun(t, path, clock, 4242, start, end, RunEndingSignal)
	noBoot := func() (time.Time, error) { return time.Time{}, errors.New("boot time unavailable") }

	raisePreviousRunFindings(st, startNext(t, path, clock), noBoot, clock.now)

	requireOneFinding(t, st, "pid 4242", "signal with no stop intent")
}

func TestPreviousRunFindingRetriesRejectedInsertAfterRestart(t *testing.T) {
	st, path := openRunStore(t)
	db, err := sql.Open("sqlite", strings.TrimSuffix(path, runRecordSuffix))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_monitor_stop BEFORE INSERT ON flags
		WHEN NEW.rule = 'monitor-stopped' BEGIN SELECT RAISE(ABORT, 'monitor stop write rejected'); END`); err != nil {
		t.Fatal(err)
	}
	clock := &runClock{}
	endedRun(t, path, clock, 4242, testBoot.Add(time.Hour), testBoot.Add(2*time.Hour), RunEndingSignal)
	second := startNext(t, path, clock)
	raisePreviousRunFindings(st, second, bootAt(testBoot), clock.now)
	if flags := monitorStoppedFlags(t, st); len(flags) != 0 {
		t.Fatalf("store accepted a rejected finding: %+v", flags)
	}

	if _, _, err := second.RecordStopIntent(); err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(time.Second)
	if ending, err := second.Stop(RunEndingSignal); err != nil || ending != RunEndingOwnerStop {
		t.Fatalf("Stop = %s, %v; want %s", ending, err, RunEndingOwnerStop)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_monitor_stop`); err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(time.Second)
	third, err := StartRun(path, 6262, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	raisePreviousRunFindings(st, third, bootAt(testBoot), clock.now)
	requireOneFinding(t, st, "pid 4242", "signal with no stop intent")
}

func TestPreviousRunFindingIsNotRepeatedWhenCleanupFails(t *testing.T) {
	st, path := openRunStore(t)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := &runClock{}
	second := startNext(t, path, clock)
	if _, _, err := second.RecordStopIntent(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Stop(RunEndingSignal); err != nil {
		t.Fatal(err)
	}

	// Simulate a stored flag whose pending record could not be cleared.
	restore := blockRunRecordWrite(t, path)
	raisePreviousRunFindings(st, second, bootAt(testBoot), clock.now)
	restore()
	first := requireOneFinding(t, st, "record could not be read")
	if n := st.AcknowledgeFlagsReason([]string{first.ID}, "reviewed"); n != 1 {
		t.Fatalf("acknowledged %d findings, want 1", n)
	}
	clock.t = clock.t.Add(time.Minute)
	third, err := StartRun(path, 6262, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	raisePreviousRunFindings(st, third, bootAt(testBoot), clock.now)

	again := requireOneFinding(t, st)
	if again.ID != first.ID || !again.TS.Equal(first.TS) || !again.Acknowledged {
		t.Fatalf("finding changed: was %+v, now %+v", first, again)
	}
}

// bootTime reads this machine's boot time: after the Unix epoch, before now.
func TestPreviousRunBootTimeIsBeforeNow(t *testing.T) {
	boot, err := bootTime()
	if err != nil {
		t.Fatal(err)
	}
	if !boot.After(time.Unix(0, 0)) || !boot.Before(time.Now()) {
		t.Fatalf("bootTime = %v, want between the epoch and now", boot)
	}
}
