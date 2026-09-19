package correlate

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// NotifyScopeStore persists per-workspace notification overrides: the
// operator's "page me for leaks in the prod repo, stay quiet in my scratch
// clones" policy. It is the third tier over the notification decision,
// strongest first:
//
//	workspace+rule  (this store)
//	rule            (NotifyRuleStore)
//	default         (severity >= DefaultNotifyMinSeverity)
//
// Keyed by workspace path prefix + rule. A true override forces notification
// even below the severity bar; false suppresses the rule for that workspace
// entirely. The path is cleaned and matched by prefix (a workspace scope
// covers the repo and anything under it), longest-prefix first — the most
// specific scope wins, same as resource workspace policies.
//
// File discipline matches the sibling stores: JSON, 0600, atomic,
// corrupt-file-loud (never silently drop a security policy).
type NotifyScopeStore struct {
	path string
	mu   sync.Mutex
}

func NewNotifyScopeStore(path string) *NotifyScopeStore {
	return &NotifyScopeStore{path: path}
}

// scopeKey is the on-disk key: workspace path + NUL + rule. NUL cannot appear
// in a path or rule id, so it is an unambiguous separator.
func scopeKey(workspace, rule string) string {
	return strings.TrimRight(workspace, "/") + "\x00" + rule
}

func splitScopeKey(k string) (workspace, rule string, ok bool) {
	i := strings.IndexByte(k, 0)
	if i < 0 {
		return "", "", false
	}
	return k[:i], k[i+1:], true
}

// Load returns the raw scope map (key = "workspace\x00rule").
func (s *NotifyScopeStore) Load() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *NotifyScopeStore) loadLocked() map[string]bool {
	raw := map[string]bool{}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return raw
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("correlate: WARNING: notify-scopes file %s is corrupt (%v); workspace scopes are NOT applied until it is fixed", s.path, err)
		return map[string]bool{}
	}
	out := make(map[string]bool, len(raw))
	for k, v := range raw {
		if _, _, ok := splitScopeKey(k); ok {
			out[k] = v
		}
	}
	return out
}

// Set records a workspace+rule override. Idempotent.
func (s *NotifyScopeStore) Set(workspace, rule string, notify bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.loadLocked()
	key := scopeKey(workspace, rule)
	if cur, ok := m[key]; ok && cur == notify {
		return nil
	}
	m[key] = notify
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}

// Clear removes a workspace+rule override. Clearing an absent scope is a no-op.
func (s *NotifyScopeStore) Clear(workspace, rule string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.loadLocked()
	key := scopeKey(workspace, rule)
	if _, ok := m[key]; !ok {
		return nil
	}
	delete(m, key)
	return safefile.WriteFileAtomic(s.path, mustJSON(m), 0o600)
}

// Lookup resolves the workspace+rule override for a flag's workspace, longest
// (most specific) prefix first. ok=false means no workspace scope applies —
// the caller falls through to the per-rule store, then the default.
func (s *NotifyScopeStore) Lookup(workspace, rule string) (notify bool, ok bool) {
	if workspace == "" || rule == "" {
		return false, false
	}
	s.mu.Lock()
	scopes := s.loadLocked()
	s.mu.Unlock()

	ws := strings.TrimRight(workspace, "/")
	bestLen := -1
	for k, v := range scopes {
		scopeWS, scopeRule, valid := splitScopeKey(k)
		if !valid || scopeRule != rule {
			continue
		}
		// Prefix match: the scope covers the workspace and its descendants.
		if ws != scopeWS && !strings.HasPrefix(ws+"/", scopeWS+"/") {
			continue
		}
		if len(scopeWS) > bestLen {
			bestLen = len(scopeWS)
			notify, ok = v, true
		}
	}
	return notify, ok
}

// Pairs lists every workspace scope as (workspace, rule, notify) for the UI.
func (s *NotifyScopeStore) Pairs() []NotifyScopePair {
	s.mu.Lock()
	scopes := s.loadLocked()
	s.mu.Unlock()
	out := make([]NotifyScopePair, 0, len(scopes))
	for k, v := range scopes {
		if ws, rule, ok := splitScopeKey(k); ok {
			out = append(out, NotifyScopePair{Workspace: ws, Rule: rule, Notify: v})
		}
	}
	return out
}

// NotifyScopePair is one workspace-scoped override for the API/UI.
type NotifyScopePair struct {
	Workspace string `json:"workspace"`
	Rule      string `json:"rule"`
	Notify    bool   `json:"notify"`
}
