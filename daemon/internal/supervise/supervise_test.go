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
