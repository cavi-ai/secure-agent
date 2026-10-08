package api

import (
	"sort"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// HarnessCoverage separates supported capabilities from recent, attributed
// activity. A timestamp is evidence for a harness, not a guarantee that every
// current session is guarded. Payload inspection is separate proxy routing.
type HarnessCoverage struct {
	Name           string `json:"name"`
	GuardSupported bool   `json:"guard_supported"`
	TraceSupported bool   `json:"trace_supported"`
	HookLastSeen   string `json:"hook_last_seen,omitempty"`
	TraceLastSeen  string `json:"trace_last_seen,omitempty"`
}

// harnessActivityTTL is how long one read of the 24 h harness activity
// serves status, posture and Doctor: the query scans a day of trace rows
// under the store lock, and a day-wide window cannot turn on 30 seconds.
const harnessActivityTTL = 30 * time.Second

// harnessActivityCache holds the last 24 h harness activity read.
type harnessActivityCache struct {
	mu   sync.Mutex
	at   time.Time
	data map[string]store.HarnessActivity
}

// recentHarnessActivity is the store's harness activity over
// hookActivityWindow, read at most once per harnessActivityTTL; concurrent
// callers share one read.
func (a *API) recentHarnessActivity() map[string]store.HarnessActivity {
	if a.store == nil {
		return nil
	}
	c := &a.harnessActivity
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) >= harnessActivityTTL {
		data, err := a.store.HarnessActivitySinceResult(time.Now().Add(-hookActivityWindow))
		if err == nil {
			c.data = data
		}
		c.at = time.Now()
	}
	return c.data
}

// harnessCoverage rows for the live agents; activity is read only when an
// agent is live.
func harnessCoverage(status Status, activity func() map[string]store.HarnessActivity) []HarnessCoverage {
	names := map[string]bool{}
	for _, agent := range status.Agents {
		if agent.Kind != "infra" && agent.Name != "" {
			names[agent.Name] = true
		}
	}
	var seen map[string]store.HarnessActivity
	if len(names) > 0 {
		seen = activity()
	}
	rows := make([]HarnessCoverage, 0, len(names))
	for name := range names {
		row := HarnessCoverage{Name: name, GuardSupported: name == "claude" || name == "cursor"}
		switch name {
		case "claude", "cursor", "codex", "antigravity", "opencode", "openclaw", "hermes":
			row.TraceSupported = true
		}
		row.HookLastSeen = seen[name].HookLastSeen
		row.TraceLastSeen = seen[name].TraceLastSeen
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

func activeHarness(status Status, name string) bool {
	for _, agent := range status.Agents {
		if agent.Kind != "infra" && agent.Name == name {
			return true
		}
	}
	return false
}

func harnessUncoveredItems(rows []HarnessCoverage) []PostureItem {
	var items []PostureItem
	for _, row := range rows {
		if row.GuardSupported && row.HookLastSeen == "" {
			items = append(items, PostureItem{Kind: "harness_uncovered", ID: "harness-hooks:" + row.Name, Severity: 2,
				Title:  row.Name + ": no guard hook activity in 24h",
				Detail: "This harness is running, but no attributed guard-hook activity was observed. Check its hook registration; tracing alone does not prove guarding."})
		}
	}
	return items
}
