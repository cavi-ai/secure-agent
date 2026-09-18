package otlp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestNilExporterIsSafe(t *testing.T) {
	// A node without otlp configured gets a nil exporter; every method must
	// no-op rather than panic (the drain loop calls them unconditionally).
	var e *Exporter
	e.SessionSpan(model.Session{ID: "s1"})
	e.TraceEvent(event.Event{Kind: event.KindToolCall, SessionID: "s1"})
	e.Wait()
	if e.Dropped() != 0 {
		t.Fatal("nil exporter dropped count must be 0")
	}
}

// A tool call and its session both land as spans in one OTLP envelope, sharing
// the session's trace id, with no secret-bearing attribute.
func TestExporterSendsSessionAndToolSpans(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := New(Config{Endpoint: srv.URL, Service: "secure-agent"}, "node-1", "v9")
	now := time.Now()
	e.SessionSpan(model.Session{ID: "sess-1", Harness: "claude", Repo: "api", Branch: "main", StartedAt: now, LastSeenAt: now, Status: "active"})
	e.TraceEvent(event.Event{
		Kind: event.KindToolCall, TS: now, SessionID: "sess-1",
		ToolName: "Bash", ToolStatus: "ok", DurationMs: 31000,
	})
	e.TraceEvent(event.Event{
		Kind: event.KindModelCall, TS: now, SessionID: "sess-1",
		Model: "claude-sonnet-4-5", TokensIn: 1000, TokensOut: 50, CostUSD: 0.00375,
	})
	e.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no OTLP export POSTed")
	}
	// Parse the first non-empty envelope.
	var env otlpEnvelope
	if err := json.Unmarshal(bodies[0], &env); err != nil {
		t.Fatalf("envelope not JSON: %v", err)
	}
	if len(env.ResourceSpans) != 1 {
		t.Fatalf("resourceSpans = %d, want 1", len(env.ResourceSpans))
	}
	spans := env.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) < 2 {
		t.Fatalf("spans = %d, want session + tool + model", len(spans))
	}
	// All spans share one trace id (the session), distinct span ids.
	traceIDs := map[string]bool{}
	spanIDs := map[string]bool{}
	names := map[string]bool{}
	for _, s := range spans {
		traceIDs[s.TraceID] = true
		spanIDs[s.SpanID] = true
		names[s.Name] = true
	}
	if len(traceIDs) != 1 {
		t.Fatalf("spans must share one trace id, got %d", len(traceIDs))
	}
	if len(spanIDs) != len(spans) {
		t.Fatalf("span ids not unique: %d ids / %d spans", len(spanIDs), len(spans))
	}
	for _, want := range []string{"session", "tool.Bash", "model.claude-sonnet-4-5"} {
		if !names[want] {
			t.Errorf("span %q missing; got %v", want, names)
		}
	}
	// Resource carries node identity; the tool span carries the duration.
	resAttrs := map[string]string{}
	for _, a := range env.ResourceSpans[0].Resource.Attributes {
		if a.Value.StringValue != nil {
			resAttrs[a.Key] = *a.Value.StringValue
		}
	}
	if resAttrs["secure_agent.node_id"] != "node-1" || resAttrs["service.version"] != "v9" {
		t.Fatalf("resource attrs = %v", resAttrs)
	}
	// No attribute value may contain a secret-shaped key.
	raw := string(bodies[0])
	for _, forbidden := range []string{"Bearer ", "sk-", "password", "PRIVATE KEY"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("OTLP body carries secret-shaped text %q", forbidden)
		}
	}
}

// A dead endpoint must not block the drain loop: enqueue stays non-blocking
// and Wait bounded (the client timeout governs the HTTP attempt).
func TestExporterNeverBlocksOnDeadEndpoint(t *testing.T) {
	e := New(Config{Endpoint: "http://127.0.0.1:1/v1/traces"}, "n", "v")
	e.client.Timeout = 200 * time.Millisecond
	start := time.Now()
	for i := 0; i < 500; i++ {
		e.TraceEvent(event.Event{Kind: event.KindTurn, TS: time.Now(), SessionID: "s1"})
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("enqueue blocked: %v for 500 events", elapsed)
	}
	e.Wait()
}
