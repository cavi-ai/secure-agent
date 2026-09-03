package main

// The JSONL store: append-only, one file per node, plus an in-memory rollup
// rebuilt on startup by replaying the log. 0600 files in a 0700 directory —
// the collector sees fleet security data and must not be the weak link.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store is the append-only JSONL log plus the in-memory rollup.
type Store struct {
	mu    sync.Mutex
	dir   string
	nodes map[string]*NodeState
	files map[string]*os.File // node_id -> open append handle
}

// NodeState is everything the rollup needs about one node.
type NodeState struct {
	NodeID         string    `json:"node_id"`
	Version        string    `json:"version"`
	LastSeen       time.Time `json:"last_seen"`
	Flags          int       `json:"flags"`
	Incidents      int       `json:"incidents"`
	GuardDecisions int       `json:"guard_decisions"`
	LatestIncident string    `json:"latest_incident,omitempty"`
	LatestFlag     string    `json:"latest_flag,omitempty"`
}

// envelopeFile is the on-disk record: the envelope plus the receipt time, so
// delivery lag is distinguishable from event time.
type envelopeFile struct {
	ReceivedAt string   `json:"received_at"`
	Envelope   Envelope `json:"envelope"`
}

func NewStore(dir string) *Store {
	s := &Store{dir: dir, nodes: map[string]*NodeState{}}
	s.replay()
	return s
}

// replay rebuilds the rollup from any existing JSONL files at startup.
func (s *Store) replay() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		nodeID := strings.TrimSuffix(e.Name(), ".jsonl")
		_ = nodeID // files carry the id; rollup rebuilds from envelope content
		f, err := os.Open(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 2<<20)
		for sc.Scan() {
			var rec envelopeFile
			if json.Unmarshal(sc.Bytes(), &rec) == nil {
				s.apply(rec.Envelope, rec.ReceivedAt)
			}
		}
		f.Close()
	}
}

// nodeFile lazily opens (and keeps open) the append handle for a node.
func (s *Store) nodeFile(nodeID string) (*os.File, error) {
	path := filepath.Join(s.dir, sanitize(nodeID)+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// sanitize keeps a node id from escaping the store directory (it arrives in a
// header an operator provisioned, but defense in depth costs one regexp).
func sanitize(nodeID string) string {
	clean := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return -1
	}, nodeID)
	if clean == "" {
		clean = "unknown-node"
	}
	return clean
}

// Append stores one verified envelope and updates the rollup.
func (s *Store) Append(env Envelope) error {
	receivedAt := time.Now().UTC().Format(time.RFC3339Nano)

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.nodeFile(env.NodeID)
	if err != nil {
		return fmt.Errorf("open append: %w", err)
	}
	defer f.Close()

	rec := envelopeFile{ReceivedAt: receivedAt, Envelope: env}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	s.apply(env, receivedAt)
	return nil
}

// apply folds one envelope into the in-memory rollup. Caller must hold mu
// (replay takes it via Append's contract; replay path is single-threaded).
func (s *Store) apply(env Envelope, receivedAt string) {
	st := s.nodes[env.NodeID]
	if st == nil {
		st = &NodeState{NodeID: env.NodeID}
		s.nodes[env.NodeID] = st
	}
	if st.Version == "" {
		st.Version = env.Version
	}
	if ts, err := time.Parse(time.RFC3339Nano, receivedAt); err == nil && ts.After(st.LastSeen) {
		st.LastSeen = ts
	}
	switch env.Kind {
	case "flag":
		st.Flags++
		st.LatestFlag = summarize(env.Payload, "rule", 120)
	case "incident":
		st.Incidents++
		st.LatestIncident = summarize(env.Payload, "summary", 200)
	case "guard":
		st.GuardDecisions++
	}
}

// summarize extracts one field from an opaque payload for the rollup line.
func summarize(payload json.RawMessage, field string, max int) string {
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		if len(v) > max {
			v = v[:max] + "…"
		}
		return v
	}
	return ""
}

// sortNodesSnapshot copies the node map into a stable node-id-ordered slice.
func sortNodesSnapshot(states map[string]*NodeState) []*NodeState {
	out := make([]*NodeState, 0, len(states))
	for _, st := range states {
		out = append(out, st)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].NodeID < out[j-1].NodeID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Rollup returns a stable-ordered copy of the node states.
func (s *Store) Rollup() []*NodeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortNodesSnapshot(s.nodes)
}

// Query replays one node's envelopes from disk, newest first, optionally
// filtered by kind.
func (s *Store) Query(nodeID string, kinds map[string]bool, limit int) []envelopeFile {
	path := filepath.Join(s.dir, sanitize(nodeID)+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var all []envelopeFile
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2<<20)
	for sc.Scan() {
		var rec envelopeFile
		if json.Unmarshal(sc.Bytes(), &rec) == nil {
			if len(kinds) > 0 && !kinds[rec.Envelope.Kind] {
				continue
			}
			all = append(all, rec)
		}
	}
	// Newest first.
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all
}
