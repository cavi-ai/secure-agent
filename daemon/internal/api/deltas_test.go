package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestDeltaOverflowDisconnectsOnlySlowSubscriber(t *testing.T) {
	h := NewDeltaHub()
	h.buf = 1
	slow, fast := h.Subscribe(), h.Subscribe()
	h.Publish(Delta{Type: "first"})
	<-fast
	h.Publish(Delta{Type: "second"})
	if got := <-fast; got.Type != "second" {
		t.Fatalf("healthy subscriber received %+v", got)
	}
	if got := <-slow; got.Type != "first" {
		t.Fatalf("buffered delivery lost: %+v", got)
	}
	select {
	case _, ok := <-slow:
		if ok {
			t.Fatal("overflowed subscriber still receiving")
		}
	default:
		t.Fatal("overflow did not close slow subscriber")
	}
	h.Unsubscribe(slow) // Already detached; must not double-close.
	reconnected := h.Subscribe()
	h.Publish(Delta{Type: "third"})
	if got := <-reconnected; got.Type != "third" {
		t.Fatalf("reconnected: %+v", got)
	}
	<-fast
	if h.Dropped() != 1 {
		t.Fatalf("drops = %d, want one missed delivery", h.Dropped())
	}
	h.Close()
	h.Close()
	h.Unsubscribe(fast)
	h.Unsubscribe(reconnected)
}

type stalledGreeting struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *stalledGreeting) Flush() {
	w.once.Do(func() { close(w.entered); <-w.release })
	w.ResponseRecorder.Flush()
}

func TestEventStreamEndsAfterOverflow(t *testing.T) {
	h := NewDeltaHub()
	h.buf = 1
	a := &API{deltaHub: h}
	w := &stalledGreeting{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleEventStream(w, httptest.NewRequest("GET", "/events/stream", nil).WithContext(ctx))
	}()
	<-w.entered
	h.Publish(Delta{Type: "event", Data: "queued"})
	h.Publish(Delta{Type: "event", Data: "missed"})
	close(w.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream stayed open after losing a delta")
	}
}

func TestDeltaLossIsSeparateFromEvidenceLoss(t *testing.T) {
	st := testStore(t)
	defer st.Close()
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	a.deltaHub = NewDeltaHub()
	a.deltaHub.buf = 1
	a.deltaHub.Subscribe()
	a.deltaHub.Publish(Delta{Type: "first"})
	a.deltaHub.Publish(Delta{Type: "missed"})
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	var status Status
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || status.DeltaDrops != 1 || status.BusDrops != 0 || status.BusDropping {
		t.Fatalf("live delivery loss conflated with evidence loss: %s", w.Body.String())
	}
	for _, item := range machineAttentionItems(time.Now(), status, guardHookUnregisteredItem(status)) {
		if item.Kind == "event_loss" || item.Kind == "storage_loss" {
			t.Fatalf("false evidence loss: %+v", item)
		}
	}
}

func TestDeltaHubConcurrentOverflowAndShutdown(t *testing.T) {
	h := NewDeltaHub()
	h.buf = 1
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				sub := h.Subscribe()
				h.Publish(Delta{Type: "event"})
				h.Publish(Delta{Type: "event"})
				h.Unsubscribe(sub)
			}
		}()
	}
	h.Close()
	workers.Wait()
	if _, ok := <-h.Subscribe(); ok {
		t.Fatal("closed hub accepted a subscription")
	}
}
