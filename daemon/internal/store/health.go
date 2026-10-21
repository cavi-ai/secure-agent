package store

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"sort"
	"sync"
	"time"
)

// WriteHealth describes best-effort evidence persistence during this daemon
// run, including failure to open a configured mirror. Active faults recover
// on the next successful write of the same kind;
// Failures never decreases because recovery cannot restore missing evidence.
// Operation names are fixed labels, never paths, SQL, or error/payload text.
// ReadActive independently reports unavailable reads until that query succeeds.
type WriteHealth struct {
	Failures uint64 `json:"failures"`
	// LastFailureAt is when Failures last grew; nil before any failure.
	LastFailureAt *time.Time  `json:"last_failure_at,omitempty"`
	Active        []string    `json:"active"`
	ReadFailures  uint64      `json:"read_failures,omitempty"`
	ReadActive    []string    `json:"read_active,omitempty"`
	ReadIssues    []ReadIssue `json:"read_issues,omitempty"`
}

// ReadIssue retains a bounded diagnostic per fixed operation label. Raw error
// text, SQL, paths and evidence values never enter the status response.
type ReadIssue struct {
	Operation      string     `json:"operation"`
	Category       string     `json:"category"`
	Failures       uint64     `json:"failures"`
	FirstFailureAt time.Time  `json:"first_failure_at"`
	LastFailureAt  time.Time  `json:"last_failure_at"`
	RecoveredAt    *time.Time `json:"recovered_at,omitempty"`
}

type writeHealth struct {
	mu            sync.Mutex // independent of database IO and Store.mu
	failures      uint64
	lastFailureAt time.Time
	active        map[string]bool
	readFailures  uint64
	readActive    map[string]bool
	readIssues    map[string]ReadIssue
}

func (s *Store) noteRead(operation string, err error) {
	// A caller abandoning a read says nothing about storage availability.
	// Preserve any earlier fault until a read actually succeeds.
	if errors.Is(err, context.Canceled) {
		return
	}
	h := &s.writeHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		delete(h.readActive, operation)
		if issue, ok := h.readIssues[operation]; ok && issue.RecoveredAt == nil {
			now := time.Now().UTC()
			issue.RecoveredAt = &now
			h.readIssues[operation] = issue
		}
		return
	}
	h.readFailures++
	if h.readActive == nil {
		h.readActive = make(map[string]bool)
	}
	h.readActive[operation] = true
	if h.readIssues == nil {
		h.readIssues = make(map[string]ReadIssue)
	}
	issue := h.readIssues[operation]
	issue.Operation, issue.Category = operation, readFailureCategory(err)
	issue.Failures++
	issue.LastFailureAt = time.Now().UTC()
	if issue.FirstFailureAt.IsZero() {
		issue.FirstFailureAt = issue.LastFailureAt
	}
	issue.RecoveredAt = nil
	h.readIssues[operation] = issue
}

func readFailureCategory(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, sql.ErrConnDone), err.Error() == "sql: database is closed":
		return "closed"
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		switch coded.Code() & 0xff {
		case 5, 6:
			return "busy"
		case 11, 26:
			return "corrupt"
		case 10, 13, 14:
			return "io"
		}
	}
	return "unavailable"
}

// noteReadLogged also logs the cause of a failed read, which the health label
// does not carry.
func (s *Store) noteReadLogged(operation string, err error) {
	if err != nil {
		log.Printf("store: %s: %v", operation, err)
	}
	s.noteRead(operation, err)
}

// noteWrite reports whether the visible health state changed. Repeated
// failures count as changes; a healthy write is quiet unless it clears a fault.
func (s *Store) noteWrite(operation string, err error) bool {
	h := &s.writeHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		changed := h.active[operation]
		delete(h.active, operation)
		return changed
	}
	h.failures++
	h.lastFailureAt = time.Now().UTC()
	if operation == "finding reviews" && !h.active[operation] {
		log.Printf("store: finding review write failed: %v", err)
	}
	if h.active == nil {
		h.active = make(map[string]bool)
	}
	h.active[operation] = true
	return true
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
	if !h.lastFailureAt.IsZero() {
		at := h.lastFailureAt
		snapshot.LastFailureAt = &at
	}
	for operation := range h.active {
		snapshot.Active = append(snapshot.Active, operation)
	}
	sort.Strings(snapshot.Active)
	snapshot.ReadFailures = h.readFailures
	for operation := range h.readActive {
		snapshot.ReadActive = append(snapshot.ReadActive, operation)
	}
	sort.Strings(snapshot.ReadActive)
	for _, issue := range h.readIssues {
		if issue.RecoveredAt != nil {
			at := *issue.RecoveredAt
			issue.RecoveredAt = &at
		}
		snapshot.ReadIssues = append(snapshot.ReadIssues, issue)
	}
	sort.Slice(snapshot.ReadIssues, func(i, j int) bool { return snapshot.ReadIssues[i].Operation < snapshot.ReadIssues[j].Operation })
	return snapshot
}
