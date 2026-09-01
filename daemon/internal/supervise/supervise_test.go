package supervise

import (
	"context"
	"errors"
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
