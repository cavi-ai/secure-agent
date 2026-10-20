package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestShutdownWaitsForCollectorsBeforeClosingBus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := bus.New(1)
	input := b.Subscribe()
	cancelled, release, collected := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	go func() {
		defer close(collected)
		<-ctx.Done()
		close(cancelled)
		<-release
		b.Publish(event.Event{Kind: event.KindFileOpen, Path: "/workspace/final.txt"})
	}()
	c := &Components{cancel: cancel, bus: b, collectorsDone: collected}
	stopped := make(chan struct{})
	go func() { c.Shutdown(); close(stopped) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel the collector")
	}
	select {
	case <-stopped:
		t.Error("shutdown returned before the collector's final work")
	case <-time.After(25 * time.Millisecond):
	}
	unblock()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after the collector exited")
	}
	if final, ok := <-input; !ok || final.Path != "/workspace/final.txt" {
		t.Fatalf("final event lost before bus closure: event=%+v open=%v", final, ok)
	}
	if _, ok := <-input; ok {
		t.Fatal("bus remains open after shutdown")
	}
}
