package store

import (
	"sort"
	"sync"
)

// WriteHealth describes best-effort evidence persistence during this daemon
// run, including failure to open a configured mirror. Active faults recover
// on the next successful write of the same kind;
// Failures never decreases because recovery cannot restore missing evidence.
// Operation names are fixed labels, never paths, SQL, or error/payload text.
// ReadActive independently reports unavailable reads until that query succeeds.
type WriteHealth struct {
	Failures     uint64   `json:"failures"`
	Active       []string `json:"active"`
	ReadFailures uint64   `json:"read_failures,omitempty"`
	ReadActive   []string `json:"read_active,omitempty"`
}

type writeHealth struct {
	mu           sync.Mutex // independent of database IO and Store.mu
	failures     uint64
	active       map[string]bool
	readFailures uint64
	readActive   map[string]bool
}

func (s *Store) noteRead(operation string, err error) {
	h := &s.writeHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		delete(h.readActive, operation)
		return
	}
	h.readFailures++
	if h.readActive == nil {
		h.readActive = make(map[string]bool)
	}
	h.readActive[operation] = true
}

func (s *Store) noteWrite(operation string, err error) {
	h := &s.writeHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		delete(h.active, operation)
		return
	}
	h.failures++
	if h.active == nil {
		h.active = make(map[string]bool)
	}
	h.active[operation] = true
}

// NoteTranscriptCheckpointWrite includes the collector's checkpoint file in
// evidence health. Only a fixed operation label enters the status snapshot.
func (s *Store) NoteTranscriptCheckpointWrite(err error) {
	s.noteWrite("transcript checkpoints", err)
}

func (s *Store) NoteOpencodeCheckpointWrite(err error) {
	s.noteWrite("opencode checkpoints", err)
}

// WriteHealth takes no database lock, so a stuck writer cannot hide its
// already-observed failures from the operator.
func (s *Store) WriteHealth() WriteHealth {
	h := &s.writeHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	snapshot := WriteHealth{Failures: h.failures, Active: []string{}}
	for operation := range h.active {
		snapshot.Active = append(snapshot.Active, operation)
	}
	sort.Strings(snapshot.Active)
	snapshot.ReadFailures = h.readFailures
	for operation := range h.readActive {
		snapshot.ReadActive = append(snapshot.ReadActive, operation)
	}
	sort.Strings(snapshot.ReadActive)
	return snapshot
}
