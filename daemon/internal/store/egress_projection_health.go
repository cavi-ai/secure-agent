package store

import "sync"

// EgressProjectionHealth counts incomplete recurring-egress summaries during
// this run. QueueDrops counts observations rejected before writing; WriteFailures
// counts failed observation transactions. These are not raw event losses.
// Recovery clears WriteFailing but cannot restore missed observations.
type EgressProjectionHealth struct {
	QueueDrops    uint64 `json:"queue_drops"`
	WriteFailures uint64 `json:"write_failures"`
	WriteFailing  bool   `json:"write_failing"`
}

type egressProjectionHealth struct {
	mu sync.Mutex // independent of database IO
	EgressProjectionHealth
}

func (s *Store) NoteEgressProjectionDrop() {
	h := &s.egressProjectionHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	h.QueueDrops++
}

// NoteEgressProjectionWrite reports whether visible projection health changed.
// Only counters and state are retained, never the error or observation payload.
func (s *Store) NoteEgressProjectionWrite(err error) bool {
	h := &s.egressProjectionHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	changed := h.WriteFailing
	h.WriteFailing = err != nil
	if err != nil {
		h.WriteFailures++
		return true
	}
	return changed
}

func (s *Store) EgressProjectionHealth() EgressProjectionHealth {
	h := &s.egressProjectionHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.EgressProjectionHealth
}
