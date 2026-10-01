package correlate

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// ReadConnectKey is the pattern one read-then-connect flag stands for:
// agent, reader (ReaderLabel), file, destination (DestLabel).
func ReadConnectKey(agent, reader, path, dest string) string {
	return agent + "|" + reader + "|" + path + "|" + dest
}

// ReaderLabel names the process that read the file: "tool" for an agent
// tool read, else its executable's lower-cased base name.
func ReaderLabel(exe string, toolRead bool) string {
	if toolRead {
		return "tool"
	}
	return strings.ToLower(filepath.Base(exe))
}

// DestLabel is an exact endpoint. Shared infrastructure must never widen
// an operator exception to every tenant of a cloud or CDN.
func DestLabel(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// ExpectedPattern is one read-then-connect pattern the operator marked
// expected. Its occurrences are counted, not flagged; a new reader, file or
// destination still flags.
type ExpectedPattern struct {
	Scope     string    `json:"scope,omitempty"` // "file": exact non-secret path for this agent
	Key       string    `json:"key"`
	Agent     string    `json:"agent"`
	Reader    string    `json:"reader"`
	Path      string    `json:"path"`
	Dest      string    `json:"dest"`
	CreatedAt time.Time `json:"created_at"`
	// Hits and LastSeen count the occurrences matched since the daemon
	// started; they are not persisted.
	Hits     int        `json:"hits"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
}

// ExpectStore persists expected patterns (JSON, 0600, atomic) and matches
// against an in-memory copy.
type ExpectStore struct {
	path    string
	mu      sync.Mutex
	loaded  bool
	entries map[string]*ExpectedPattern
}

type expectedOnDisk struct {
	Scope     string    `json:"scope,omitempty"`
	Agent     string    `json:"agent"`
	Reader    string    `json:"reader"`
	Path      string    `json:"path"`
	Dest      string    `json:"dest"`
	CreatedAt time.Time `json:"created_at"`
}

func NewExpectStore(path string) *ExpectStore {
	return &ExpectStore{path: path}
}

func (s *ExpectStore) loadLocked() {
	if s.loaded {
		return
	}
	s.loaded = true
	s.entries = map[string]*ExpectedPattern{}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var disk []expectedOnDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		log.Printf("correlate: WARNING: expected-patterns file %s is corrupt (%v); none are applied until it is fixed", s.path, err)
		return
	}
	for _, d := range disk {
		key := ReadConnectKey(d.Agent, d.Reader, d.Path, d.Dest)
		s.entries[key] = &ExpectedPattern{Scope: d.Scope, Key: key, Agent: d.Agent, Reader: d.Reader, Path: d.Path, Dest: d.Dest, CreatedAt: d.CreatedAt}
	}
}

func (s *ExpectStore) saveLocked() error {
	disk := make([]expectedOnDisk, 0, len(s.entries))
	for _, e := range s.sortedLocked() {
		disk = append(disk, expectedOnDisk{Scope: e.Scope, Agent: e.Agent, Reader: e.Reader, Path: e.Path, Dest: e.Dest, CreatedAt: e.CreatedAt})
	}
	return safefile.WriteFileAtomic(s.path, mustJSON(disk), 0o600)
}

func (s *ExpectStore) sortedLocked() []ExpectedPattern {
	out := make([]ExpectedPattern, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// List returns the expected patterns, oldest first.
func (s *ExpectStore) List() []ExpectedPattern {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	return s.sortedLocked()
}

// Add records p (its Key is derived) and returns the stored entry. Adding a
// pattern already present returns it unchanged.
func (s *ExpectStore) Add(p ExpectedPattern) (ExpectedPattern, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	p.Key = ReadConnectKey(p.Agent, p.Reader, p.Path, p.Dest)
	if e, ok := s.entries[p.Key]; ok {
		return *e, nil
	}
	p.Hits, p.LastSeen = 0, nil
	s.entries[p.Key] = &p
	if err := s.saveLocked(); err != nil {
		delete(s.entries, p.Key)
		return ExpectedPattern{}, err
	}
	return p, nil
}

// Remove forgets one pattern; false when it was not stored.
func (s *ExpectStore) Remove(key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	e, ok := s.entries[key]
	if !ok {
		return false, nil
	}
	delete(s.entries, key)
	if err := s.saveLocked(); err != nil {
		s.entries[key] = e
		return false, err
	}
	return true, nil
}

// Has reports whether key is expected, without counting a hit.
func (s *ExpectStore) Has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	return s.matchLocked(key) != nil
}

// Match reports whether every key is expected and, when so, counts one hit
// on each at at.
func (s *ExpectStore) Match(keys []string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	if len(keys) == 0 {
		return false
	}
	for _, k := range keys {
		if s.matchLocked(k) == nil {
			return false
		}
	}
	for _, k := range keys {
		e := s.matchLocked(k)
		e.Hits++
		if e.LastSeen == nil || at.After(*e.LastSeen) {
			t := at
			e.LastSeen = &t
		}
	}
	return true
}

// A file exception is exact-path and agent-scoped. Delimit from the ends so
// a pipe in a file name cannot broaden the exception to a neighboring path.
func (s *ExpectStore) matchLocked(key string) *ExpectedPattern {
	if e := s.entries[key]; e != nil {
		return e
	}
	agent, rest, ok := strings.Cut(key, "|")
	if !ok {
		return nil
	}
	_, rest, ok = strings.Cut(rest, "|")
	if !ok {
		return nil
	}
	i := strings.LastIndex(rest, "|")
	if i < 0 {
		return nil
	}
	e := s.entries[ReadConnectKey(agent, "*", rest[:i], "*")]
	if e != nil && e.Scope == "file" {
		return e
	}
	return nil
}
