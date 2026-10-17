package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// A privileged collector installed after launch starts file telemetry once,
// without a daemon restart.
func TestWatchSpoolStartsTelemetryWhenTheCollectorAppears(t *testing.T) {
	var checks, starts atomic.Int32
	done := make(chan struct{})
	go func() {
		watchSpool(context.Background(), time.Millisecond, func() bool { return checks.Add(1) >= 3 }, func() { starts.Add(1) })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("watchSpool never started telemetry")
	}
	if checks.Load() != 3 || starts.Load() != 1 {
		t.Fatalf("checks=%d starts=%d, want 3 and 1", checks.Load(), starts.Load())
	}
}

// Shutdown ends the watch without starting anything.
func TestWatchSpoolStopsWithTheDaemon(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var starts atomic.Int32
	done := make(chan struct{})
	go func() {
		watchSpool(ctx, time.Millisecond, func() bool { return false }, func() { starts.Add(1) })
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("watchSpool outlived its context")
	}
	if starts.Load() != 0 {
		t.Fatal("started telemetry after shutdown")
	}
}
