// Package fleet delivers security events to downstream fleet collectors over
// HMAC-signed webhooks. It is the pull-API companion: nodes stay serverless;
// collectors receive flags, incidents, guard decisions, and status heartbeats
// as they happen.
package fleet

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// EventKind names the payload types a webhook can be subscribed to.
type EventKind string

const (
	EventFlag     EventKind = "flag"
	EventIncident EventKind = "incident"
	EventGuard    EventKind = "guard"
	// EventStatus is the periodic heartbeat/posture envelope. It is NOT a
	// subscribable event kind: it flows to every sink regardless of the
	// configured events filter, because liveness that can be filtered out is
	// indistinguishable from a dead node.
	EventStatus EventKind = "status"
)

// Valid reports whether k is a known subscription kind.
func (k EventKind) Valid() bool {
	switch k {
	case EventFlag, EventIncident, EventGuard:
		return true
	}
	return false
}

// WebhookConfig is one signed sink, from config.yaml.
type WebhookConfig = config.WebhookConfig

// Envelope is the JSON body POSTed to every sink. NodeID ties the event to a
// machine; TS is the delivery time, not the event time (Payload.TS carries that).
// Boot+Seq give the collector gap detection: Boot identifies one daemon run,
// Seq is a per-boot monotonic counter stamped by the Publisher, so a dropped
// delivery (backlog cap, dead collector, restart) shows up as a missing
// number instead of vanishing silently.
type Envelope struct {
	NodeID  string          `json:"node_id"`
	Kind    string          `json:"kind"`
	TS      string          `json:"ts"`
	Version string          `json:"version"`
	Boot    string          `json:"boot,omitempty"`
	Seq     uint64          `json:"seq,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

// Sink delivers envelopes to one configured webhook with HMAC signing, bounded
// retry, and a local delivery log so operators can see what left the node.
type Sink struct {
	url     string
	secret  []byte
	kinds   map[string]bool
	client  *http.Client
	nodeID  string
	version string

	logMu   sync.Mutex
	logPath string
}

// maxBody bounds a single webhook payload; findings are redacted upstream and
// small — a runaway payload is a bug, not something to ship.
const maxBody = 1 << 20

// NewSink builds a sink for one webhook config. url/secret empty disables it.
func NewSink(cfg WebhookConfig, nodeID, version, logDir string) *Sink {
	if cfg.URL == "" || cfg.Secret == "" {
		return nil
	}
	kinds := map[string]bool{}
	for _, k := range cfg.Events {
		kinds[k] = true
	}
	var lp string
	if logDir != "" {
		lp = filepath.Join(logDir, "webhook-deliveries.jsonl")
	}
	return &Sink{
		url:     cfg.URL,
		secret:  []byte(cfg.Secret),
		kinds:   kinds,
		nodeID:  nodeID,
		version: version,
		// A stuck collector must never pin a daemon goroutine.
		client:  &http.Client{Timeout: 10 * time.Second},
		logPath: lp,
	}
}

// Subscribed reports whether this sink wants events of kind k. Status
// heartbeats always flow (see EventStatus); event kinds honor the filter.
func (s *Sink) Subscribed(k EventKind) bool {
	if s == nil {
		return false
	}
	if k == EventStatus {
		return true
	}
	if len(s.kinds) == 0 {
		return true
	}
	return s.kinds[string(k)]
}

// Deliver marshals payload and POSTs it as an envelope. Retries: 1 initial
// attempt + 3 retries (4 total), 500ms/2s/5s backoff, only on retryable
// (network / 5xx / 429) failures.
// Deliver never blocks longer than ~20s worst case; callers run it in a
// goroutine per event. seq/boot are the Publisher-stamped gap-detection
// coordinates (0/"" for direct Deliver callers — pre-sequence legacy).
func (s *Sink) Deliver(kind EventKind, payload any, seq uint64, boot string) {
	if !s.Subscribed(kind) {
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		s.record(kind, s.url, 0, "payload-marshal-error")
		return
	}
	env := Envelope{
		NodeID:  s.nodeID,
		Kind:    string(kind),
		TS:      time.Now().UTC().Format(time.RFC3339Nano),
		Version: s.version,
		Boot:    boot,
		Seq:     seq,
		Payload: json.RawMessage(raw),
	}
	body, err := json.Marshal(env)
	if err != nil || len(body) > maxBody {
		s.record(kind, s.url, 0, "marshal-error-or-oversize")
		return
	}

	backoff := []time.Duration{500 * time.Millisecond, 2 * time.Second, 5 * time.Second}
	var lastErr string
	for attempt := 0; ; attempt++ {
		status, err := s.post(body)
		if err == nil && status >= 200 && status < 300 {
			s.record(kind, s.url, status, "")
			return
		}
		if err != nil {
			lastErr = err.Error()
		} else {
			lastErr = fmt.Sprintf("http %d", status)
		}
		retryable := err != nil || status == http.StatusTooManyRequests || status >= 500
		if !retryable || attempt >= len(backoff) {
			s.record(kind, s.url, status, lastErr)
			log.Printf("webhook: delivery to %s failed after %d attempt(s): %s", s.url, attempt+1, lastErr)
			return
		}
		time.Sleep(backoff[attempt])
	}
}

// post sends one signed request. Signature header:
//
//	X-SecureAgent-Signature: sha256=<hex hmac-sha256(secret, body)>
//
// Timestamped-override schemes (t=,v1=) are deliberately simple here: the body
// carries ts, and replay within a local tailnet is out of the threat model
// stated in docs/FIREWALL_THREAT_MODEL.md.
func (s *Sink) post(body []byte) (int, error) {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SecureAgent-Signature", sig)
	req.Header.Set("X-SecureAgent-Node", s.nodeID)
	req.Header.Set("User-Agent", "secure-agentd/"+s.version)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// record appends one line to the delivery log (best-effort, never fatal).
func (s *Sink) record(kind EventKind, url string, status int, errMsg string) {
	if s.logPath == "" {
		return
	}
	rec := map[string]any{
		"ts":     time.Now().UTC().Format(time.RFC3339Nano),
		"kind":   string(kind),
		"url":    url,
		"status": status,
	}
	if errMsg != "" {
		rec["error"] = errMsg
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.logPath), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(s.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}
