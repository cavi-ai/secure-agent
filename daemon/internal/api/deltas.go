package api

import (
	"slices"
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
// instant path keys on them). Guard lifecycle notifications are live control
// signals and remain available when event persistence fails.
type Delta struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// DeltaHub is a non-blocking fan-out for typed deltas, mirroring the event
// bus discipline: a slow subscriber drops rather than stalling the drain
// loop. Overflow closes and detaches that subscription so SSE clients
// reconnect and reconcile. Missed deliveries are surfaced as /status delta_drops;
// they do not imply loss of persisted evidence.
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
			h.subs = slices.Delete(h.subs, i, i+1)
			if !h.done {
				close(sub)
			}
			return
		}
	}
}

// Publish never blocks: a wedged console must not slow the drain loop.
func (h *DeltaHub) Publish(d Delta) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done {
		return
	}
	for i := 0; i < len(h.subs); {
		ch := h.subs[i]
		select {
		case ch <- d:
			i++
		default:
			h.dropped.Add(1)
			close(ch)
			h.subs = slices.Delete(h.subs, i, i+1)
		}
	}
}

// Dropped counts subscriber deliveries rejected at overflow, before detachment.
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
	h.subs = nil
}
