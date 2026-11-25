package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// Each stop path writes its ending to the run record; a signal counts as an
// owner stop only inside StopIntentWindow after a stop intent.
func TestRunRecordEndings(t *testing.T) {
	t0 := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		intent  time.Duration // offset from start; 0 records no intent
		stop    time.Duration // offset from start when the trigger fires
		trigger string
		want    RunEnding
	}{
		{"stop after an intent", 2 * time.Second, 5 * time.Second, "signal", RunEndingOwnerStop},
		{"stop with no intent", 0, 5 * time.Second, "signal", RunEndingSignal},
		{"stop after an expired intent", time.Second, 2*time.Second + StopIntentWindow, "signal", RunEndingSignal},
		{"parent exit", 0, 5 * time.Second, "parent", RunEndingParentExit},
		{"parent exit after an intent", 2 * time.Second, 5 * time.Second, "parent", RunEndingParentExit},
		{"control API failure", 0, 5 * time.Second, "api", RunEndingAPIFailure},
		{"shutdown with no stop trigger", 0, 5 * time.Second, "none", RunEndingStartFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "run-record.json")
			now := t0
			tr, err := StartRun(path, 4242, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if tc.intent > 0 {
				now = t0.Add(tc.intent)
				at, until, err := tr.RecordStopIntent()
				if err != nil {
					t.Fatal(err)
				}
				if !at.Equal(now) || !until.Equal(now.Add(StopIntentWindow)) {
					t.Fatalf("intent %s valid until %s, want %s until %s", at, until, now, now.Add(StopIntentWindow))
				}
			}
			now = t0.Add(tc.stop)

			c := &Components{run: tr, apiErrors: make(chan error, 1)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			parentGone := make(chan struct{})
			switch tc.trigger {
			case "signal":
				cancel()
			case "parent":
				close(parentGone)
			case "api":
				c.apiErrors <- errors.New("listener closed")
			}
			if tc.trigger != "none" {
				err := c.waitForStop(ctx, parentGone)
				if (tc.trigger == "api") != (err != nil) {
					t.Fatalf("waitForStop: %v", err)
				}
			}
			c.Shutdown()

			prev, found, err := ReadPreviousRun(path)
			if err != nil || !found {
				t.Fatalf("read back: found=%v err=%v", found, err)
			}
			if prev.Ending != tc.want || prev.Record.Ending != tc.want {
				t.Fatalf("ending %q (record %q), want %q", prev.Ending, prev.Record.Ending, tc.want)
			}
			if prev.Record.PID != 4242 || !prev.Record.StartedAt.Equal(t0) || !prev.Record.EndedAt.Equal(t0.Add(tc.stop)) {
				t.Fatalf("record %+v, want pid 4242 started %s ended %s", prev.Record, t0, t0.Add(tc.stop))
			}
			if tc.intent > 0 && !prev.Record.StopIntentAt.Equal(t0.Add(tc.intent)) {
				t.Fatalf("stop intent %s, want %s", prev.Record.StopIntentAt, t0.Add(tc.intent))
			}
		})
	}
}

// A start that finds the previous run's running marker without an ending
// reports that run as ended without a record, then writes its own marker.
func TestRunRecordStartFindsRecordWithoutEnding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-record.json")
	t0 := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	first, err := StartRun(path, 100, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.RecordStopIntent(); err != nil {
		t.Fatal(err)
	}

	if _, err := StartRun(path, 200, func() time.Time { return t0.Add(time.Minute) }); err != nil {
		t.Fatal(err)
	}
	state, found, err := readRunState(path)
	if err != nil || !found || len(state.Pending) != 1 {
		t.Fatalf("read back: pending=%+v found=%v err=%v, want one previous run", state.Pending, found, err)
	}
	prev := state.Pending[0]
	if prev.Ending != RunEndingNoRecord {
		t.Fatalf("previous run ending %q, want %q", prev.Ending, RunEndingNoRecord)
	}
	if prev.Record.PID != 100 || !prev.Record.StartedAt.Equal(t0) || !prev.Record.EndedAt.IsZero() {
		t.Fatalf("previous record %+v, want pid 100 started %s with no end", prev.Record, t0)
	}

	onDisk, found, err := ReadPreviousRun(path)
	if err != nil || !found {
		t.Fatalf("read back: found=%v err=%v", found, err)
	}
	if onDisk.Record.PID != 200 || onDisk.Record.Ending != "" || !onDisk.Record.StopIntentAt.IsZero() {
		t.Fatalf("persisted record %+v, want the second run's running marker", onDisk.Record)
	}
}

func TestRunRecordFailedIntentKeepsPreviousIntent(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		name := "first intent"
		if refresh {
			name = "refresh"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "run-record.json")
			now := time.Now().UTC()
			tr, err := StartRun(path, 100, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			var accepted time.Time
			if refresh {
				accepted, _, err = tr.RecordStopIntent()
				if err != nil {
					t.Fatal(err)
				}
			}

			now = now.Add(StopIntentWindow)
			restore := blockRunRecordWrite(t, path)
			if _, _, err := tr.RecordStopIntent(); err == nil {
				t.Fatal("stop intent succeeded with the record path blocked")
			}
			restore()
			now = now.Add(time.Second)

			if ending, err := tr.Stop(RunEndingSignal); err != nil || ending != RunEndingSignal {
				t.Fatalf("Stop returned %q, %v, want signal after an unrecorded intent", ending, err)
			}
			prev, found, err := ReadPreviousRun(path)
			if err != nil || !found || !prev.Record.StopIntentAt.Equal(accepted) {
				t.Fatalf("read back: intent=%s found=%v err=%v, want intent %s", prev.Record.StopIntentAt, found, err, accepted)
			}
		})
	}
}

func TestRunRecordShutdownRetriesFirstEnding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-record.json")
	now := time.Now().UTC()
	tr, err := StartRun(path, 100, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	firstEnd := now
	restore := blockRunRecordWrite(t, path)
	if ending, err := tr.Stop(RunEndingSignal); err == nil || ending != RunEndingSignal {
		t.Fatalf("Stop returned %q, %v, want signal and a write error", ending, err)
	}
	restore()
	now = now.Add(time.Second)
	(&Components{run: tr}).Shutdown()

	prev, found, err := ReadPreviousRun(path)
	if err != nil || !found || prev.Ending != RunEndingSignal || !prev.Record.EndedAt.Equal(firstEnd) {
		t.Fatalf("read back: %+v found=%v err=%v, want signal at %s", prev, found, err, firstEnd)
	}
}

func blockRunRecordWrite(t *testing.T, path string) func() {
	t.Helper()
	saved := path + ".saved"
	if err := os.Rename(path, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(saved, path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunRecordIsolatedByInstance(t *testing.T) {
	for _, name := range []string{"database", "in-memory"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			first := config.Config{SocketPath: filepath.Join(dir, "first.sock")}
			first.Firewall.Registry.SaltRef = filepath.Join(dir, "salt")
			second := first
			second.SocketPath = filepath.Join(dir, "second.sock")
			if name == "database" {
				first.DBPath = filepath.Join(dir, "first.db")
				second.DBPath = filepath.Join(dir, "second.db")
			}
			firstPath, secondPath := RunRecordPath(first), RunRecordPath(second)
			if _, err := StartRun(firstPath, 100, time.Now); err != nil {
				t.Fatal(err)
			}
			if _, err := StartRun(secondPath, 200, time.Now); err != nil {
				t.Fatal(err)
			}
			state, found, err := readRunState(secondPath)
			if err != nil || !found || len(state.Pending) != 0 {
				t.Fatalf("second instance record: pending=%+v found=%v err=%v, want no previous run", state.Pending, found, err)
			}
			prev, found, err := ReadPreviousRun(firstPath)
			if err != nil || !found || prev.Record.PID != 100 {
				t.Fatalf("first instance record: %+v found=%v err=%v, want PID 100", prev, found, err)
			}
			if first.DBPath != "" {
				first.SocketPath = second.SocketPath
				if got := RunRecordPath(first); got != firstPath {
					t.Fatalf("changing the socket moved the database's run record to %q, want %q", got, firstPath)
				}
			}
		})
	}
}
