package bus

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestPublishFansOutToAllSubscribers(t *testing.T) {
	b := New(8)
	defer b.Close()
	a := b.Subscribe()
	c := b.Subscribe()

	b.Publish(event.Event{Kind: event.KindExec, PID: 42})

	for i, ch := range []<-chan event.Event{a, c} {
		select {
		case e := <-ch:
			if e.PID != 42 {
				t.Fatalf("subscriber %d got PID %d, want 42", i, e.PID)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d received nothing", i)
		}
	}
}

func TestPublishDropsWhenSubscriberFull(t *testing.T) {
	b := New(1) // buffer of 1
	defer b.Close()
	_ = b.Subscribe()
	// Two publishes with no reader: must not block or panic.
	done := make(chan struct{})
	go func() {
		b.Publish(event.Event{Kind: event.KindExec})
		b.Publish(event.Event{Kind: event.KindExec})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked when subscriber buffer was full")
	}
}
