package otlp

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDroppedCountsEverySpanInRejectedBatch(t *testing.T) {
	e := New(Config{Endpoint: "http://unused.invalid"}, "n", "v")
	e.flushInterval = time.Hour
	for i := 0; i < cap(e.sem); i++ {
		e.sem <- struct{}{}
	}
	for i := 0; i < 100; i++ {
		e.enqueue(span{name: "test"})
	}
	e.Flush()
	if got := e.Dropped(); got != 100 {
		t.Fatalf("dropped = %d, want 100 spans", got)
	}
}

func TestExportRecoveryKeepsLostSpanCount(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	e := New(Config{Endpoint: srv.URL}, "n", "v")
	defer e.Wait()
	e.flushInterval = time.Hour
	e.enqueue(span{name: "lost"})
	e.Flush()
	e.wg.Wait()
	if !e.Failing() || e.Dropped() != 1 {
		t.Fatal("failed export not reported")
	}
	failing.Store(false)
	e.enqueue(span{name: "recovered"})
	e.Flush()
	e.wg.Wait()
	if e.Failing() || e.Dropped() != 1 {
		t.Fatal("recovery did not separate current health from history")
	}
}

func TestFailedExportCountsLostSpans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	e := New(Config{Endpoint: srv.URL}, "n", "v")
	e.flushInterval = time.Hour
	e.enqueue(span{name: "a"})
	e.enqueue(span{name: "b"})
	e.Wait()
	if got := e.Dropped(); got != 2 {
		t.Fatalf("dropped = %d, want 2 failed spans", got)
	}
}
