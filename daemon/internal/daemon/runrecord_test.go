package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
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
	if prev, found := first.Previous(); found {
		t.Fatalf("first start found a previous run: %+v", prev)
	}
	if _, _, err := first.RecordStopIntent(); err != nil {
		t.Fatal(err)
	}

	second, err := StartRun(path, 200, func() time.Time { return t0.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	prev, found := second.Previous()
	if !found || prev.Ending != RunEndingNoRecord {
		t.Fatalf("previous run found=%v ending %q, want %q", found, prev.Ending, RunEndingNoRecord)
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
