package collect

import (
	"cmp"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// PlanWindow is one rate-limit window of a subscription plan.
type PlanWindow struct {
	WindowMinutes int     `json:"window_minutes"`
	UsedPercent   float64 `json:"used_percent"`
	ResetsAt      string  `json:"resets_at"` // RFC3339; "" when not reported
}

// PlanSnapshot is the latest plan headroom one harness home reported.
type PlanSnapshot struct {
	Harness   string       `json:"harness"`
	Home      string       `json:"home"` // CodexHomeLabel of the home
	PlanType  string       `json:"plan_type"`
	LimitID   string       `json:"limit_id"`
	Windows   []PlanWindow `json:"windows"` // primary first, then secondary when reported
	Unlimited bool         `json:"unlimited"`
	SeenAt    time.Time    `json:"seen_at"` // timestamp of the line that carried it
}

// plans holds the newest snapshot per home directory, in memory only.
var plans = struct {
	mu     sync.Mutex
	byHome map[string]PlanSnapshot
}{byHome: map[string]PlanSnapshot{}}

// RecordPlan keeps s as home's snapshot unless the one held was seen later.
func RecordPlan(home string, s PlanSnapshot) {
	plans.mu.Lock()
	defer plans.mu.Unlock()
	if old, ok := plans.byHome[home]; ok && old.SeenAt.After(s.SeenAt) {
		return
	}
	s.Windows = slices.Clone(s.Windows)
	plans.byHome[home] = s
}

// Plans returns every home's snapshot sorted by label, then newest first.
func Plans() []PlanSnapshot {
	plans.mu.Lock()
	out := make([]PlanSnapshot, 0, len(plans.byHome))
	for _, s := range plans.byHome {
		s.Windows = slices.Clone(s.Windows)
		out = append(out, s)
	}
	plans.mu.Unlock()
	slices.SortFunc(out, func(a, b PlanSnapshot) int {
		return cmp.Or(strings.Compare(a.Home, b.Home), b.SeenAt.Compare(a.SeenAt))
	})
	return out
}

// codexHomeOf returns the Codex home a rollout path lives under: the prefix
// before its last "/sessions/" ("" when there is none).
func codexHomeOf(path string) string {
	i := strings.LastIndex(path, "/sessions/")
	if i <= 0 {
		return ""
	}
	return path[:i]
}

// CodexHomeLabel names the Codex home of a rollout path: "codex" for the
// default home (a .codex directory), "<name> (openclaw)" for an openclaw
// agent's …/.openclaw/agents/<name>/agent/codex-home, else the home's base
// name; "" when the path is under no sessions directory. Pure.
func CodexHomeLabel(path string) string {
	home := codexHomeOf(path)
	if home == "" {
		return ""
	}
	base := filepath.Base(home)
	if base == ".codex" {
		return "codex"
	}
	parts := strings.Split(home, "/")
	if n := len(parts); n >= 5 && parts[n-1] == "codex-home" && parts[n-2] == "agent" &&
		parts[n-4] == "agents" && parts[n-5] == ".openclaw" && parts[n-3] != "" {
		return parts[n-3] + " (openclaw)"
	}
	return base
}
