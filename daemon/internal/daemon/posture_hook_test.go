package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Marks never wait for the recompute, and a burst of marks costs one
// recompute after the burst.
func TestPostureHookCoalescesOffTheCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	h := newPostureHook(100 * time.Millisecond)
	h.start(ctx, func() { calls.Add(1); time.Sleep(50 * time.Millisecond) })
	start := time.Now()
	for range 20 {
		h.run()
	}
	if elapsed := time.Since(start); elapsed > 25*time.Millisecond {
		t.Fatalf("20 posture marks held the caller for %v", elapsed)
	}
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("recomputes for one burst = %d, want 1", got)
	}
}

// A mark made while a recompute runs is not lost: it starts one more pass.
func TestPostureHookRecomputesAgainAfterAMarkDuringRecompute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	running, release := make(chan struct{}), make(chan struct{})
	passes := make(chan int32, 4)
	var calls atomic.Int32
	h := newPostureHook(time.Millisecond)
	h.start(ctx, func() {
		n := calls.Add(1)
		if n == 1 {
			close(running)
			<-release
		}
		passes <- n
	})
	h.run()
	<-running
	h.run()
	close(release)
	for want := int32(1); want <= 2; want++ {
		select {
		case got := <-passes:
			if got != want {
				t.Fatalf("pass %d, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("pass %d never ran", want)
		}
	}
}
