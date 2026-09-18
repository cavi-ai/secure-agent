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
	"sync"
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
	s.Deliver(EventFlag, map[string]any{"rule": "aws-key"}, 0, "")

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
	go func() { s.Deliver(EventIncident, map[string]any{"id": "x"}, 0, ""); close(done) }()
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
	s.Deliver(EventGuard, map[string]any{"x": 1}, 0, "")
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (4xx not retryable)", calls.Load())
	}
}

func TestDeliveryLogWritten(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	s := NewSink(WebhookConfig{URL: srv.URL, Secret: "s"}, "n", "v", dir)
	s.Deliver(EventFlag, map[string]any{"a": 1}, 0, "")

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

// Status heartbeats must bypass the per-sink kind filter: liveness that can
// be unsubscribed is indistinguishable from a dead node.
func TestSinkStatusBypassesKindFilter(t *testing.T) {
	s := NewSink(WebhookConfig{URL: "http://127.0.0.1:1", Secret: "x", Events: []string{"flag"}}, "node", "v1", "")
	if !s.Subscribed(EventStatus) {
		t.Fatal("status must flow even when the sink subscribes to flag only")
	}
	if s.Subscribed(EventGuard) {
		t.Fatal("guard must stay filtered out")
	}
	if !s.Subscribed(EventFlag) {
		t.Fatal("flag must stay subscribed")
	}
	var nilSink *Sink
	if nilSink.Subscribed(EventStatus) {
		t.Fatal("nil sink subscribes to nothing")
	}
}

func TestPublisherHasSinks(t *testing.T) {
	p := NewPublisher()
	if p.HasSinks() {
		t.Fatal("empty publisher must report no sinks")
	}
	p.AddSink(nil) // ignored
	if p.HasSinks() {
		t.Fatal("nil sink must not count")
	}
	p.AddSink(NewSink(WebhookConfig{URL: "http://127.0.0.1:1", Secret: "x"}, "node", "v1", ""))
	if !p.HasSinks() {
		t.Fatal("publisher with one sink must report sinks")
	}
}

// Every Publish stamps the next per-boot sequence number and a stable boot
// id — the collector's gap detection depends on both.
func TestPublisherStampsBootAndSeq(t *testing.T) {
	var mu sync.Mutex
	var got []Envelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env Envelope
		if json.NewDecoder(r.Body).Decode(&env) == nil {
			mu.Lock()
			got = append(got, env)
			mu.Unlock()
		}
	}))
	defer srv.Close()

	p := NewPublisher()
	p.AddSink(NewSink(WebhookConfig{URL: srv.URL, Secret: "s"}, "n", "v", ""))
	p.Publish(EventFlag, map[string]any{"id": "1"})
	p.Publish(EventIncident, map[string]any{"id": "2"})
	p.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("received %d envelopes, want 2", len(got))
	}
	// Delivery order isn't guaranteed (concurrent goroutines); sort by seq.
	if got[0].Seq > got[1].Seq {
		got[0], got[1] = got[1], got[0]
	}
	if got[0].Seq != 1 || got[1].Seq != 2 {
		t.Fatalf("seqs = %d,%d, want 1,2", got[0].Seq, got[1].Seq)
	}
	if got[0].Boot == "" || got[0].Boot != got[1].Boot {
		t.Fatalf("boot ids must be non-empty and stable within a run: %q %q", got[0].Boot, got[1].Boot)
	}
	if got[0].Boot != p.BootID() {
		t.Fatalf("envelope boot %q != publisher boot %q", got[0].Boot, p.BootID())
	}
}

// ReplaceSinks swaps the sink set atomically — the hot-reload path.
func TestPublisherReplaceSinks(t *testing.T) {
	var hitsA, hitsB atomic.Int32
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsA.Add(1) }))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsB.Add(1) }))
	defer srvB.Close()

	p := NewPublisher()
	p.AddSink(NewSink(WebhookConfig{URL: srvA.URL, Secret: "s"}, "n", "v", ""))
	p.ReplaceSinks([]*Sink{NewSink(WebhookConfig{URL: srvB.URL, Secret: "s"}, "n", "v", "")})
	p.Publish(EventFlag, map[string]any{"id": "1"})
	p.Wait()
	if hitsA.Load() != 0 || hitsB.Load() != 1 {
		t.Fatalf("after replace: A=%d (want 0), B=%d (want 1)", hitsA.Load(), hitsB.Load())
	}
	p.ReplaceSinks(nil) // unenroll
	if p.HasSinks() {
		t.Fatal("nil replace must leave no sinks")
	}
}

// Regression: sequence numbers are per-sink. A kind a collector does not
// subscribe to must not advance its counter — the shared counter fabricated
// gaps and the e2e caught it (session envelopes pushed a security-only
// collector's seq past 1 with nothing delivered).
func TestPublisherSeqIsPerSinkBySubscription(t *testing.T) {
	var mu sync.Mutex
	var got []Envelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env Envelope
		if json.NewDecoder(r.Body).Decode(&env) == nil {
			mu.Lock()
			got = append(got, env)
			mu.Unlock()
		}
	}))
	defer srv.Close()

	p := NewPublisher()
	// This collector wants only flags and incidents, not sessions/traces.
	p.AddSink(NewSink(WebhookConfig{URL: srv.URL, Secret: "s", Events: []string{"flag", "incident"}}, "n", "v", ""))
	p.Publish(EventSession, map[string]any{"id": "s1"})  // not subscribed: no seq burn
	p.Publish(EventTrace, map[string]any{"id": "t1"})    // not subscribed
	p.Publish(EventFlag, map[string]any{"id": "f1"})     // seq 1
	p.Publish(EventIncident, map[string]any{"id": "i1"}) // seq 2
	p.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("received %d envelopes, want 2 (unsubscribed kinds must not deliver)", len(got))
	}
	if got[0].Seq > got[1].Seq {
		got[0], got[1] = got[1], got[0]
	}
	if got[0].Seq != 1 || got[1].Seq != 2 {
		t.Fatalf("seqs = %d,%d, want 1,2 (no gap from unsubscribed kinds)", got[0].Seq, got[1].Seq)
	}
}

// A status heartbeat always flows even to a sink that subscribes to nothing
// else (liveness must be gap-visible).
func TestPublisherStatusAlwaysDelivers(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.Add(1) }))
	defer srv.Close()

	p := NewPublisher()
	p.AddSink(NewSink(WebhookConfig{URL: srv.URL, Secret: "s", Events: []string{"flag"}}, "n", "v", ""))
	p.Publish(EventStatus, map[string]any{"hostname": "n1"})
	p.Wait()
	if got.Load() != 1 {
		t.Fatalf("status heartbeats = %d, want 1", got.Load())
	}
}
