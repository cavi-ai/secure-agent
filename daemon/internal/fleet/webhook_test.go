package fleet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSinkSignsAndDelivers(t *testing.T) {
	var gotSig, gotBody string
	var gotNode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-SecureAgent-Signature")
		gotNode = r.Header.Get("X-SecureAgent-Node")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewSink(WebhookConfig{URL: srv.URL, Secret: "sekrit", Events: []string{"flag"}}, "node-1", "v1", "")
	if s == nil {
		t.Fatal("sink nil with valid config")
	}
	s.Deliver(EventFlag, map[string]any{"rule": "aws-key"})

	mac := hmac.New(sha256.New, []byte("sekrit"))
	mac.Write([]byte(gotBody))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature mismatch: got %q want %q", gotSig, want)
	}
	if gotNode != "node-1" {
		t.Fatalf("node header = %q", gotNode)
	}
	var env Envelope
	if err := json.Unmarshal([]byte(gotBody), &env); err != nil {
		t.Fatal(err)
	}
	if env.Kind != "flag" || env.NodeID != "node-1" {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestSinkDisabledWithoutSecret(t *testing.T) {
	if s := NewSink(WebhookConfig{URL: "http://x"}, "n", "v", ""); s != nil {
		t.Fatal("sink must be nil without secret")
	}
}

func TestSinkRetriesOn500ThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewSink(WebhookConfig{URL: srv.URL, Secret: "s"}, "n", "v", "")
	// Shrink backoff so the test is fast.
	done := make(chan struct{})
	go func() { s.Deliver(EventIncident, map[string]any{"id": "x"}); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("delivery did not finish (retries stuck?)")
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3 (2 retries)", calls.Load())
	}
}

func TestSinkDoesNotRetry4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(400)
	}))
	defer srv.Close()
	s := NewSink(WebhookConfig{URL: srv.URL, Secret: "s"}, "n", "v", "")
	s.Deliver(EventGuard, map[string]any{"x": 1})
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (4xx not retryable)", calls.Load())
	}
}

func TestDeliveryLogWritten(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	s := NewSink(WebhookConfig{URL: srv.URL, Secret: "s"}, "n", "v", dir)
	s.Deliver(EventFlag, map[string]any{"a": 1})

	b, err := os.ReadFile(filepath.Join(dir, "webhook-deliveries.jsonl"))
	if err != nil {
		t.Fatalf("delivery log missing: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(b[:len(b)-1], &rec); err != nil {
		t.Fatalf("bad log line: %v", err)
	}
	if rec["kind"] != "flag" || rec["status"] != float64(200) {
		t.Fatalf("log record = %v", rec)
	}
}

func TestPublisherFansOutToSubscribedSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	p := NewPublisher()
	p.AddSink(NewSink(WebhookConfig{URL: srv.URL, Secret: "s", Events: []string{"flag"}}, "n", "v", ""))
	p.AddSink(NewSink(WebhookConfig{URL: srv.URL, Secret: "s", Events: []string{"guard"}}, "n", "v", ""))
	p.AddSink(nil) // disabled entries are ignored

	p.Publish(EventFlag, map[string]any{"id": "1"})
	p.Wait()
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1 (only flag-subscribed sink fires)", hits.Load())
	}
}
