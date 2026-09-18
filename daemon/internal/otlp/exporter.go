// Package otlp exports the trace model (sessions, tool calls, model calls,
// turns) as OTLP/HTTP JSON spans, so secure-agent's own telemetry can land in
// any OpenTelemetry backend (Tempo, Jaeger, Honeycomb, Datadog…). It is the
// "don't reinvent the backend" exit: the daemon keeps the session spine and
// the trace, and OTLP is the standard wire out.
//
// Delivery is best-effort and bounded exactly like the fleet webhooks: a slow
// or dead collector must never stall the drain loop, so publishes are dropped
// (counted) past the in-flight cap. No secrets cross this wire — spans carry
// tool names, models, durations and token counts, never file contents or
// command text.
package otlp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Config is one OTLP/HTTP endpoint plus its identity attributes.
type Config struct {
	Endpoint string            // full URL, e.g. http://127.0.0.1:4318/v1/traces
	Headers  map[string]string // e.g. api-key for hosted backends
	Service  string            // resource service.name (default "secure-agent")
	Labels   map[string]string // extra resource attributes
}

// maxInFlight bounds concurrent exports; overflow is dropped and counted.
const maxInFlight = 32

const exportTimeout = 10 * time.Second

// Exporter batches spans and POSTs them as OTLP/HTTP JSON.
type Exporter struct {
	cfg     Config
	client  *http.Client
	nodeID  string
	version string

	mu       sync.Mutex
	batch    []span
	timer    *time.Timer
	flushing bool

	sem     chan struct{}
	wg      sync.WaitGroup
	dropped atomic.Uint64

	// Batch tuning: small bursts flush fast; a busy session batches.
	flushInterval time.Duration
	maxBatch      int
}

// span is one OTLP span before serialization.
type span struct {
	traceID    string
	spanID     string
	name       string
	start      time.Time
	end        time.Time
	attributes map[string]any
	statusCode string // "", "STATUS_CODE_OK", "STATUS_CODE_ERROR"
}

// New builds an exporter. Empty endpoint disables it (nil).
func New(cfg Config, nodeID, version string) *Exporter {
	if cfg.Endpoint == "" {
		return nil
	}
	if cfg.Service == "" {
		cfg.Service = "secure-agent"
	}
	return &Exporter{
		cfg:           cfg,
		client:        &http.Client{Timeout: exportTimeout},
		nodeID:        nodeID,
		version:       version,
		sem:           make(chan struct{}, maxInFlight),
		flushInterval: 500 * time.Millisecond,
		maxBatch:      256,
	}
}

// SessionSpan records a session's identity as a span attribute set on every
// child — a tool call without its session is useless in a trace backend.
func (e *Exporter) SessionSpan(sess model.Session) {
	if e == nil {
		return
	}
	e.enqueue(span{
		traceID: traceID(sess.ID),
		spanID:  spanID(sess.ID, "session"),
		name:    "session",
		start:   sess.StartedAt,
		end:     endOr(sess.EndedAt, sess.LastSeenAt),
		attributes: map[string]any{
			"session.id":         sess.ID,
			"session.harness":    sess.Harness,
			"session.repo":       sess.Repo,
			"session.branch":     sess.Branch,
			"session.workspace":  sess.Workspace,
			"session.status":     sess.Status,
			"session.confidence": sess.Confidence,
		},
		statusCode: "STATUS_CODE_OK",
	})
}

// TraceEvent records one agent-semantic event (tool call, model call, turn).
func (e *Exporter) TraceEvent(ev event.Event) {
	if e == nil || ev.SessionID == "" {
		return
	}
	switch ev.Kind {
	case event.KindToolCall:
		start := ev.TS
		end := start.Add(time.Duration(ev.DurationMs) * time.Millisecond)
		status := "STATUS_CODE_OK"
		if ev.ToolStatus == "error" {
			status = "STATUS_CODE_ERROR"
		}
		e.enqueue(span{
			traceID: traceID(ev.SessionID),
			spanID:  spanID(ev.SessionID, fmt.Sprintf("tool-%d-%s", ev.TS.UnixNano(), ev.ToolName)),
			name:    "tool." + ev.ToolName,
			start:   start,
			end:     end,
			attributes: map[string]any{
				"tool.name":        ev.ToolName,
				"tool.status":      ev.ToolStatus,
				"tool.duration_ms": ev.DurationMs,
				"session.id":       ev.SessionID,
			},
			statusCode: status,
		})
	case event.KindModelCall:
		e.enqueue(span{
			traceID: traceID(ev.SessionID),
			spanID:  spanID(ev.SessionID, fmt.Sprintf("model-%d", ev.TS.UnixNano())),
			name:    "model." + ev.Model,
			start:   ev.TS,
			end:     ev.TS,
			attributes: map[string]any{
				"gen_ai.request.model":  ev.Model,
				"gen_ai.usage.input":    ev.TokensIn,
				"gen_ai.usage.output":   ev.TokensOut,
				"gen_ai.usage.cost_usd": ev.CostUSD,
				"session.id":            ev.SessionID,
			},
			statusCode: "STATUS_CODE_OK",
		})
	case event.KindTurn:
		e.enqueue(span{
			traceID:    traceID(ev.SessionID),
			spanID:     spanID(ev.SessionID, fmt.Sprintf("turn-%d", ev.TS.UnixNano())),
			name:       "turn",
			start:      ev.TS,
			end:        ev.TS,
			attributes: map[string]any{"session.id": ev.SessionID},
			statusCode: "STATUS_CODE_OK",
		})
	}
}

// enqueue appends to the batch and schedules a flush. Never blocks: past the
// in-flight cap the span is dropped and counted.
func (e *Exporter) enqueue(s span) {
	e.mu.Lock()
	if len(e.batch) >= e.maxBatch {
		e.mu.Unlock()
		e.dropped.Add(1)
		return
	}
	e.batch = append(e.batch, s)
	needTimer := e.timer == nil
	if needTimer {
		e.timer = time.AfterFunc(e.flushInterval, e.Flush)
	}
	e.mu.Unlock()
}

// Flush ships the current batch. Safe to call concurrently and directly
// (shutdown).
func (e *Exporter) Flush() {
	e.mu.Lock()
	if len(e.batch) == 0 {
		if e.timer != nil {
			e.timer.Stop()
			e.timer = nil
		}
		e.mu.Unlock()
		return
	}
	batch := e.batch
	e.batch = nil
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	e.mu.Unlock()

	select {
	case e.sem <- struct{}{}:
	default:
		e.dropped.Add(1)
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() { <-e.sem }()
		if err := e.post(batch); err != nil {
			log.Printf("otlp: export failed (%d spans): %v", len(batch), err)
		}
	}()
}

// Wait blocks until in-flight exports settle (shutdown).
func (e *Exporter) Wait() {
	if e == nil {
		return
	}
	e.Flush()
	e.wg.Wait()
}

// Dropped counts spans dropped past the in-flight cap or batch size.
func (e *Exporter) Dropped() uint64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

// post serializes the OTLP envelope and POSTs it.
func (e *Exporter) post(batch []span) error {
	body, err := json.Marshal(e.envelope(batch))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), exportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp: endpoint answered %d", resp.StatusCode)
	}
	return nil
}

// --- OTLP/HTTP JSON envelope (the subset every backend accepts) ---

type otlpEnvelope struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

type resourceSpans struct {
	Resource   resource     `json:"resource"`
	ScopeSpans []scopeSpans `json:"scopeSpans"`
}

type resource struct {
	Attributes []attribute `json:"attributes"`
}

type scopeSpans struct {
	Scope scope      `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type scope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpSpan struct {
	TraceID           string      `json:"traceId"`
	SpanID            string      `json:"spanId"`
	Name              string      `json:"name"`
	Kind              int         `json:"kind"` // 1 = INTERNAL
	StartTimeUnixNano string      `json:"startTimeUnixNano"`
	EndTimeUnixNano   string      `json:"endTimeUnixNano"`
	Attributes        []attribute `json:"attributes"`
	Status            spanStatus  `json:"status"`
}

type spanStatus struct {
	Code string `json:"code,omitempty"`
}

type attribute struct {
	Key   string       `json:"key"`
	Value attributeVal `json:"value"`
}

// attributeVal is the OTLP "AnyValue" oneof; we emit string/int/double/bool.
type attributeVal struct {
	StringValue *string  `json:"stringValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"` // OTLP JSON uses string for int64
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
}

func (e *Exporter) envelope(batch []span) otlpEnvelope {
	attrs := []attribute{
		strAttr("service.name", e.cfg.Service),
		strAttr("service.version", e.version),
		strAttr("secure_agent.node_id", e.nodeID),
	}
	for k, v := range e.cfg.Labels {
		attrs = append(attrs, strAttr(k, v))
	}
	spans := make([]otlpSpan, 0, len(batch))
	for _, s := range batch {
		spans = append(spans, otlpSpan{
			TraceID:           s.traceID,
			SpanID:            s.spanID,
			Name:              s.name,
			Kind:              1,
			StartTimeUnixNano: fmt.Sprintf("%d", s.start.UnixNano()),
			EndTimeUnixNano:   fmt.Sprintf("%d", s.end.UnixNano()),
			Attributes:        anyAttrs(s.attributes),
			Status:            spanStatus{Code: s.statusCode},
		})
	}
	return otlpEnvelope{ResourceSpans: []resourceSpans{{
		Resource:   resource{Attributes: attrs},
		ScopeSpans: []scopeSpans{{Scope: scope{Name: "secure-agent", Version: e.version}, Spans: spans}},
	}}}
}

func anyAttrs(m map[string]any) []attribute {
	out := make([]attribute, 0, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out = append(out, strAttr(k, t))
		case int:
			s := fmt.Sprintf("%d", t)
			out = append(out, attribute{Key: k, Value: attributeVal{IntValue: &s}})
		case int64:
			s := fmt.Sprintf("%d", t)
			out = append(out, attribute{Key: k, Value: attributeVal{IntValue: &s}})
		case float64:
			out = append(out, attribute{Key: k, Value: attributeVal{DoubleValue: &t}})
		case bool:
			b := t
			out = append(out, attribute{Key: k, Value: attributeVal{BoolValue: &b}})
		default:
			out = append(out, strAttr(k, fmt.Sprintf("%v", v)))
		}
	}
	return out
}

func strAttr(k, v string) attribute {
	s := v
	return attribute{Key: k, Value: attributeVal{StringValue: &s}}
}

// traceID derives a stable 16-byte OTLP trace id from the session id. OTLP
// ids are hex; a session maps to exactly one trace so every tool/model call
// nests under it in the backend.
func traceID(sessionID string) string {
	sum := sha256.Sum256([]byte("sa-trace:" + sessionID))
	return hex.EncodeToString(sum[:16])
}

// spanID derives a stable 8-byte OTLP span id from session + discriminator.
func spanID(sessionID, disc string) string {
	sum := sha256.Sum256([]byte("sa-span:" + sessionID + ":" + disc))
	return hex.EncodeToString(sum[:8])
}

func endOr(ended *time.Time, fallback time.Time) time.Time {
	if ended != nil && !ended.IsZero() {
		return *ended
	}
	if !fallback.IsZero() {
		return fallback
	}
	return time.Now()
}
