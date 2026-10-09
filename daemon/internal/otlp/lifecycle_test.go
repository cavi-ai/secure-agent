package otlp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func countRequestSpans(r *http.Request) (int, error) {
	var envelope otlpEnvelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		return 0, err
	}
	n := 0
	for _, resource := range envelope.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
			n += len(scope.Spans)
		}
	}
	return n, nil
}

func TestWaitClosesAdmissionAndCountsLateSpans(t *testing.T) {
	var mu sync.Mutex
	received := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := countRequestSpans(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		received += n
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer server.Close()
	e := New(Config{Endpoint: server.URL}, "fixture-node", "fixture-version")
	e.flushInterval = time.Hour
	e.TraceEvent(event.Event{Kind: event.KindTurn, SessionID: "before-shutdown", TS: time.Now()})
	e.Wait()
	e.TraceEvent(event.Event{Kind: event.KindTurn, SessionID: "after-shutdown", TS: time.Now()})
	e.Flush()
	e.Wait()
	mu.Lock()
	defer mu.Unlock()
	if received != 1 || e.Dropped() != 1 {
		t.Fatalf("received %d spans, dropped %d; want 1 each", received, e.Dropped())
	}
}

func TestConcurrentFlushAndShutdownAccountForEverySpan(t *testing.T) {
	var mu sync.Mutex
	received := 0
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := countRequestSpans(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		received += n
		mu.Unlock()
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(200)
	}))
	defer server.Close()
	defer unblock()
	e := New(Config{Endpoint: server.URL}, "fixture-node", "fixture-version")
	e.flushInterval = time.Millisecond
	e.TraceEvent(event.Event{Kind: event.KindTurn, SessionID: "initial", TS: time.Now()})
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("initial export did not reach collector")
	}
	const producers, perProducer = 8, 32
	begin := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < producers; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			<-begin
			for j := 0; j < perProducer; j++ {
				e.TraceEvent(event.Event{Kind: event.KindTurn, SessionID: fmt.Sprintf("fixture-%d-%d", worker, j), TS: time.Now()})
				e.Flush()
			}
		}(worker)
	}
	const waiters = 4
	done := make(chan struct{}, waiters)
	for j := 0; j < waiters; j++ {
		go func() { <-begin; e.Wait(); done <- struct{}{} }()
	}
	close(begin)
	workers.Wait()
	select {
	case <-done:
		t.Fatal("shutdown returned while an export was still blocked")
	default:
	}
	unblock()
	for j := 0; j < waiters; j++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("shutdown did not join exports")
		}
	}
	e.Wait() // concurrent/repeated shutdown must remain safe
	mu.Lock()
	got := received
	mu.Unlock()
	if uint64(got)+e.Dropped() != 1+producers*perProducer {
		t.Fatalf("received %d, dropped %d; want %d accounted spans", got, e.Dropped(), 1+producers*perProducer)
	}
}
