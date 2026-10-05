package api

import (
	"sort"
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

func harnessCoverage(st *store.Store, status Status) []HarnessCoverage {
	names := map[string]bool{}
	for _, agent := range status.Agents {
		if agent.Kind != "infra" && agent.Name != "" {
			names[agent.Name] = true
		}
	}
	var activity map[string]store.HarnessActivity
	if st != nil && len(names) > 0 {
		activity = st.HarnessActivitySince(time.Now().Add(-hookActivityWindow))
	}
	rows := make([]HarnessCoverage, 0, len(names))
	for name := range names {
		row := HarnessCoverage{Name: name, GuardSupported: name == "claude" || name == "cursor"}
		switch name {
		case "claude", "cursor", "codex", "agy", "opencode", "openclaw", "hermes":
			row.TraceSupported = true
		}
		row.HookLastSeen = activity[name].HookLastSeen
		row.TraceLastSeen = activity[name].TraceLastSeen
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
