package supervise

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestSupervisorRestartsAndStopsOnCancel(t *testing.T) {
	var count int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Run(ctx, "test-worker", func(c context.Context) error {
		atomic.AddInt32(&count, 1)
		if atomic.LoadInt32(&count) < 3 {
			return errors.New("simulated error")
		}
		<-c.Done()
		return c.Err()
	})

	for i := 0; i < 20; i++ {
		if atomic.LoadInt32(&count) >= 3 {
			cancel()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("worker count = %d, want >= 3", atomic.LoadInt32(&count))
}

// A worker that keeps failing must be restarted through the grace window (a boot
// transient must not permanently disable a collector) and only then abandoned —
// visibly, in the health registry, never as a silent Running:true.
func TestSupervisorRestartsThenAbandonsAfterGrace(t *testing.T) {
	var count int32
	reg := NewRegistry()
	s := New(reg)
	s.MaxBackoff = 5 * time.Millisecond
	s.MinHealthy = time.Hour // never treat these fast failures as healthy
	s.AbandonAfter = 150 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.Run(ctx, "always-fails", func(c context.Context) error {
			atomic.AddInt32(&count, 1)
			return errors.New("permanent failure")
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("supervisor never abandoned a permanently-failing worker")
	}

	// It should have restarted several times across the grace window, not given
	// up after the first couple of fast failures.
	if got := atomic.LoadInt32(&count); got < 3 {
		t.Fatalf("worker ran %d times; want >= 3 restarts before abandoning", got)
	}
	snap := reg.Snapshot()
	if len(snap) != 1 || !snap[0].Abandoned || snap[0].Running {
		t.Fatalf("health = %+v; want one abandoned, not-running worker", snap)
	}
	if snap[0].LastError == "" {
		t.Fatal("abandoned worker health should carry the last error")
	}
}

// A worker that panics must be recovered and restarted, never crash the daemon.
func TestSupervisorRecoversPanic(t *testing.T) {
	var count int32
	s := New(nil)
	s.MaxBackoff = 5 * time.Millisecond
	s.MinHealthy = time.Hour
	s.AbandonAfter = 0 // never abandon; we only care that panics don't propagate

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go s.Run(ctx, "panics", func(c context.Context) error {
		n := atomic.AddInt32(&count, 1)
		if n < 3 {
			panic("boom")
		}
		<-c.Done()
		return c.Err()
	})

	for i := 0; i < 40; i++ {
		if atomic.LoadInt32(&count) >= 3 {
			cancel()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("worker ran %d times; a recovered panic should have let it restart to 3", atomic.LoadInt32(&count))
}

// A permanent failure is deterministic: retrying cannot help, so the
// supervisor must abandon on the FIRST one instead of burning the full
// transient window (a 3-minute retry loop for "not privileged" is log spam
// and a dead telemetry path wearing a busy costume).
func TestSupervisorAbandonsImmediatelyOnPermanentError(t *testing.T) {
	var runs int32
	s := New(nil)
	s.MaxBackoff = 5 * time.Millisecond
	s.MinHealthy = time.Hour
	s.AbandonAfter = time.Hour // would eventually abandon; the test proves it never gets there

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx, "perm", func(c context.Context) error {
			atomic.AddInt32(&runs, 1)
			return Permanent(fmt.Errorf("eslogger: not privileged"))
		})
	}()

	select {
	case <-done:
		// Abandoned after the first run.
	case <-time.After(2 * time.Second):
		t.Fatalf("worker ran %d times; a permanent error must abandon on the first failure", atomic.LoadInt32(&runs))
	}
	if n := atomic.LoadInt32(&runs); n != 1 {
		t.Fatalf("worker ran %d times; permanent failure must not retry", n)
	}
}

// MarkProduced is the coverage heartbeat: a running worker that has never
// produced is distinguishable from one producing now (liveness ≠ coverage).
func TestMarkProducedStampsCoverage(t *testing.T) {
	reg := NewRegistry()
	reg.update("netsampler", func(h *Health) { h.Running = true })

	snap := reg.Snapshot()
	if snap[0].LastProduced != "" {
		t.Fatalf("LastProduced = %q, want empty before any produce", snap[0].LastProduced)
	}

	reg.MarkProduced("netsampler")
	snap = reg.Snapshot()
	ts, err := time.Parse(time.RFC3339, snap[0].LastProduced)
	if err != nil {
		t.Fatalf("LastProduced %q not RFC3339: %v", snap[0].LastProduced, err)
	}
	if time.Since(ts) > time.Minute {
		t.Fatalf("LastProduced %q is stale", snap[0].LastProduced)
	}

	// Nil registry is a no-op, never a panic (collectors run unwired in tests).
	var nilReg *Registry
	nilReg.MarkProduced("x")
}

// Coverage heartbeats carry across restarts: LoadLastProduced seeds the map,
// a worker registering later inherits the carried stamp, and PersistLastProduced
// returns the current heartbeats for the next run. Without this, every daemon
// restart reset the silence clock and the boot grace hid a dead collector for
// another ten minutes.
func TestLastProducedCarriesAcrossRestart(t *testing.T) {
	reg := NewRegistry()
	reg.LoadLastProduced(map[string]string{"eslogger": "2026-09-19T12:00:00Z"})
	reg.update("eslogger", func(h *Health) { h.Running = true })
	snap := reg.Snapshot()
	if len(snap) != 1 || snap[0].LastProduced != "2026-09-19T12:00:00Z" {
		t.Fatalf("carried stamp lost: %+v", snap)
	}
	// A fresh produce overwrites the carried value.
	reg.MarkProduced("eslogger")
	snap = reg.Snapshot()
	ts, err := time.Parse(time.RFC3339, snap[0].LastProduced)
	if err != nil || time.Since(ts) > time.Minute {
		t.Fatalf("fresh stamp = %+v err=%v", snap[0].LastProduced, err)
	}
	persisted := reg.PersistLastProduced()
	if persisted["eslogger"] != snap[0].LastProduced {
		t.Fatalf("persisted = %+v, want the fresh stamp", persisted)
	}
	// MarkProduced on an unwired worker is still recorded for persistence.
	reg.MarkProduced("transcript")
	if reg.PersistLastProduced()["transcript"] == "" {
		t.Fatal("unregistered worker's heartbeat must still persist")
	}
}
