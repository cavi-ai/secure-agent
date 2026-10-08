package fleet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTraceFloodLeavesCapacityForCriticalFlag(t *testing.T) {
	release := make(chan struct{})
	flag := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env Envelope
		json.NewDecoder(r.Body).Decode(&env)
		if env.Kind == string(EventTrace) {
			<-release
		} else {
			flag <- struct{}{}
		}
	}))
	defer srv.Close()
	defer close(release)
	p := NewPublisher()
	p.AddSink(NewSink(WebhookConfig{URL: srv.URL, Secret: "test"}, "n", "v", ""))
	for i := 0; i < 64; i++ {
		p.Publish(EventTrace, map[string]any{"id": i})
	}
	p.Publish(EventFlag, map[string]any{"id": "critical"})
	select {
	case <-flag:
	case <-time.After(time.Second):
		t.Fatal("trace deliveries starved critical flag")
	}
}

func TestReloadPreservesCollectorSequence(t *testing.T) {
	seqs := make(chan uint64, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env Envelope
		json.NewDecoder(r.Body).Decode(&env)
		seqs <- env.Seq
	}))
	defer srv.Close()
	p := NewPublisher()
	cfg := WebhookConfig{URL: srv.URL, Secret: "test"}
	p.AddSink(NewSink(cfg, "n", "v", ""))
	p.Publish(EventFlag, map[string]any{"id": "first"})
	p.Wait()
	p.ReplaceSinks([]*Sink{NewSink(cfg, "n", "v", "")})
	p.Publish(EventFlag, map[string]any{"id": "second"})
	p.Wait()
	if first, second := <-seqs, <-seqs; first != 1 || second != 2 {
		t.Fatalf("reload sequence: %d,%d", first, second)
	}
}
