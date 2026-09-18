package api

import (
	"sync"
	"sync/atomic"
)

// Delta is a typed state change pushed to SSE subscribers. Clients patch
// local state from deltas; /snapshot stays for initial load and periodic
// reconciliation only — the full-payload refetch per raw bus event is over.
//
// Types: "event" (a persisted, session-attributed event), "flag",
// "incident" (created or re-aggregated), "session" (upsert/lifecycle),
// "posture" (state or count changed), and the guard lifecycle pair
// "guard-prompt" / "guard-resolved" (kept as their own names: the menubar's
// instant path keys on them).
type Delta struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// DeltaHub is a non-blocking fan-out for typed deltas, mirroring the event
// bus discipline: a slow subscriber drops rather than stalling the drain
// loop; drops are counted and surfaced via /status bus_drops.
type DeltaHub struct {
	mu      sync.RWMutex
	buf     int
	subs    []chan Delta
	done    bool
	dropped atomic.Uint64
}

func NewDeltaHub() *DeltaHub { return &DeltaHub{buf: 256} }

func (h *DeltaHub) Subscribe() <-chan Delta {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan Delta, h.buf)
	if h.done {
		close(ch)
		return ch
	}
	h.subs = append(h.subs, ch)
	return ch
}

func (h *DeltaHub) Unsubscribe(ch <-chan Delta) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, sub := range h.subs {
		if sub == ch {
			h.subs = append(h.subs[:i], h.subs[i+1:]...)
			if !h.done {
				close(sub)
			}
			return
		}
	}
}

// Publish never blocks: a wedged console must not slow the drain loop.
func (h *DeltaHub) Publish(d Delta) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.done {
		return
	}
	for _, ch := range h.subs {
		select {
		case ch <- d:
		default:
			h.dropped.Add(1)
		}
	}
}

// Dropped counts publishes that found a full subscriber buffer.
func (h *DeltaHub) Dropped() uint64 { return h.dropped.Load() }

func (h *DeltaHub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done {
		return
	}
	h.done = true
	for _, ch := range h.subs {
		close(ch)
	}
}
