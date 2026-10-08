package otlp

import (
	"net/http"
	"net/http/httptest"
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
