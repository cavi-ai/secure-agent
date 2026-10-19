package store

import (
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// HookIngestionSnapshot describes collector delivery in this daemon run,
// across all sessions. Acceptance is not proof of storage or host connectivity.
type HookIngestionSnapshot struct {
	Available           bool                    `json:"available"`
	Since               time.Time               `json:"since"`
	Harnesses           []HookIngestionHarness  `json:"harnesses"`
	Rejected            uint64                  `json:"rejected"`
	LastRejectedAt      *time.Time              `json:"last_rejected_at,omitempty"`
	Forwarders          []HookForwarderSnapshot `json:"forwarders,omitempty"`
	ForwardersTruncated bool                    `json:"forwarders_truncated,omitempty"`
}

type HookIngestionHarness struct {
	Harness        string    `json:"harness"`
	Accepted       uint64    `json:"accepted"`
	LastReceivedAt time.Time `json:"last_received_at"`
}

type hookIngestionHealth struct {
	mu sync.Mutex
	HookIngestionSnapshot
	forwarders map[string]HookForwarderSnapshot
}

// TrackHookIngestion enables diagnostics once, preserving counters across
// collector restarts. No source paths, rejected input or session IDs are kept.
func (s *Store) TrackHookIngestion() {
	h := &s.hookIngestion
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.Available {
		h.Available = true
		h.Since = time.Now().UTC()
	}
}

func (s *Store) NoteHookAccepted(harness string) {
	// Bound cardinality to the shared contract, even for a mistaken caller.
	if !model.IsHookHarness(harness) {
		return
	}
	h := &s.hookIngestion
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.Available {
		return
	}
	now := time.Now().UTC()
	for i := range h.Harnesses {
		if h.Harnesses[i].Harness == harness {
			h.Harnesses[i].Accepted++
			h.Harnesses[i].LastReceivedAt = now
			return
		}
	}
	h.Harnesses = append(h.Harnesses, HookIngestionHarness{Harness: harness, Accepted: 1, LastReceivedAt: now})
}

// NoteHookRejected counts recognized invalid shared records. Untrusted
// session and harness fields are deliberately not used for attribution.
func (s *Store) NoteHookRejected() {
	h := &s.hookIngestion
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.Available {
		return
	}
	h.Rejected++
	now := time.Now().UTC()
	h.LastRejectedAt = &now
}

func (s *Store) HookIngestion() HookIngestionSnapshot {
	return s.hookIngestionAt(time.Now().UTC())
}

func (s *Store) hookIngestionAt(now time.Time) HookIngestionSnapshot {
	h := &s.hookIngestion
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.HookIngestionSnapshot
	out.Harnesses = append([]HookIngestionHarness{}, h.Harnesses...)
	out.Forwarders = forwarderSnapshots(h.forwarders, now)
	if h.LastRejectedAt != nil {
		at := *h.LastRejectedAt
		out.LastRejectedAt = &at
	}
	return out
}
