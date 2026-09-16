package api

import "sort"

// AgentTree is one session: the tagged root plus its helpers. The daemon
// emits this so the console and menubar do not regroup the flat agent list.
type AgentTree struct {
	Root       AgentSummary   `json:"root"`
	Children   []AgentSummary `json:"children"`
	RSSBytes   uint64         `json:"rss_bytes,omitempty"`
	CPUPercent float64        `json:"cpu_percent,omitempty"`
	LastSeen   string         `json:"last_seen_at,omitempty"`
}

// GroupAgentTrees folds a flat tagged-process list into session trees
// (root_pid). Sort is last-activity descending — same glance order as the
// session board.
func GroupAgentTrees(agents []AgentSummary) []AgentTree {
	if len(agents) == 0 {
		return []AgentTree{}
	}
	var roots []AgentSummary
	for _, a := range agents {
		if isTreeRoot(a, agents) {
			roots = append(roots, a)
		}
	}
	out := make([]AgentTree, 0, len(roots))
	for _, root := range roots {
		kids := treeChildren(root, agents)
		var rss uint64
		var cpu float64
		last := root.LastSeenAt
		if root.RSSBytes > 0 {
			rss += root.RSSBytes
		}
		cpu += root.CPUPercent
		for _, k := range kids {
			rss += k.RSSBytes
			cpu += k.CPUPercent
			if k.LastSeenAt != "" && k.LastSeenAt > last {
				last = k.LastSeenAt
			}
		}
		out = append(out, AgentTree{Root: root, Children: kids, RSSBytes: rss, CPUPercent: cpu, LastSeen: last})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen > out[j].LastSeen
	})
	return out
}

func isTreeRoot(a AgentSummary, members []AgentSummary) bool {
	if a.RootPID != 0 {
		return a.RootPID == a.PID
	}
	for _, m := range members {
		if m.PID == a.PPID {
			return false
		}
	}
	return true
}

func treeChildren(root AgentSummary, members []AgentSummary) []AgentSummary {
	kids := []AgentSummary{}
	for _, m := range members {
		if m.PID == root.PID {
			continue
		}
		r := m.RootPID
		if r == 0 {
			r = m.PPID
		}
		if r == root.PID {
			kids = append(kids, m)
		}
	}
	return kids
}
