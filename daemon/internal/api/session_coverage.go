package api

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type CoveragePath struct {
	Supported bool   `json:"supported"`
	State     string `json:"state"`
	LastSeen  string `json:"last_seen,omitempty"`
	Detail    string `json:"detail"`
}

// A setup probe is intentionally absent here: manually exercising a hook
// does not demonstrate that a running agent invokes it.
type SessionCoverage struct {
	SessionID     string       `json:"session_id,omitempty"`
	Harness       string       `json:"harness"`
	Workspace     string       `json:"workspace,omitempty"`
	RootPID       int32        `json:"root_pid"`
	IdentityBasis string       `json:"identity_basis"`
	Guard         CoveragePath `json:"guard"`
	Trace         CoveragePath `json:"trace"`
	Payload       CoveragePath `json:"payload"`
}

type sessionCoverageCache struct {
	mu    sync.Mutex
	key   string
	at    time.Time
	facts []store.SessionCoverageFact
	stale bool
}

func supportsTrace(name string) bool {
	switch name {
	case "claude", "cursor", "codex", "antigravity", "opencode", "openclaw", "hermes":
		return true
	}
	return false
}

func coveragePath(supported bool, seen, detail string, now time.Time) CoveragePath {
	p := CoveragePath{Supported: supported, State: "not-observed", Detail: detail}
	if !supported {
		p.State = "unsupported"
	}
	if at, err := time.Parse(time.RFC3339Nano, seen); err == nil && !at.After(now) && !at.Before(now.Add(-hookActivityWindow)) {
		p.LastSeen = seen
		if supported {
			p.State = "observed"
		}
	}
	return p
}

func (a *API) stampSessionCoverage(st Status, cov *CoverageStatus) {
	now := time.Now().UTC()
	roots := []AgentSummary{}
	for _, tree := range GroupAgentTrees(st.Agents) {
		if tree.Root.Kind != "infra" {
			roots = append(roots, tree.Root)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].PID < roots[j].PID })
	if len(roots) > 128 {
		roots = roots[:128]
		cov.SessionsTruncated = true
	}
	pids := []int32{}
	key := strings.Builder{}
	for _, root := range roots {
		pids = append(pids, root.PID)
		fmt.Fprintf(&key, "%d:%s:%s;", root.PID, root.Name, root.StartedAt)
	}
	c := &a.sessionCoverage
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key != key.String() {
		c.key = key.String()
		c.at = time.Time{}
		c.facts = nil
		c.stale = false
	}
	if c.at.IsZero() || now.Sub(c.at) >= harnessActivityTTL {
		if a.store == nil {
			c.stale = true
		} else {
			facts, err := a.store.SessionCoverageSince(pids, now.Add(-hookActivityWindow), now)
			c.stale = err != nil
			if err == nil {
				c.facts = facts
			}
		}
		c.at = now
	}
	cov.SessionsStale = c.stale
	cov.Sessions = []SessionCoverage{}
	for _, root := range roots {
		row := SessionCoverage{Harness: root.Name, RootPID: root.PID, Workspace: root.CWD, IdentityBasis: "unresolved"}
		var fact store.SessionCoverageFact
		matches := 0
		rootAt, rootErr := time.Parse(time.RFC3339Nano, root.StartedAt)
		for _, candidate := range c.facts {
			at, err := time.Parse(time.RFC3339Nano, candidate.RootStartedAt)
			if rootErr == nil && err == nil && at.Equal(rootAt) && candidate.RootPID == root.PID && candidate.Harness == root.Name {
				fact = candidate
				matches++
			}
		}
		if matches == 1 {
			row.SessionID = fact.ID
			row.Workspace = fact.Workspace
			row.IdentityBasis = fact.Confidence
		} else {
			fact = store.SessionCoverageFact{}
		}
		guardSeen := fact.HookLastSeen
		decisionAt, decisionErr := time.Parse(time.RFC3339Nano, fact.DecisionLastSeen)
		hookAt, hookErr := time.Parse(time.RFC3339Nano, guardSeen)
		if decisionErr == nil && (hookErr != nil || decisionAt.After(hookAt)) {
			guardSeen = fact.DecisionLastSeen
		}
		row.Guard = coveragePath(root.Name == "claude" || root.Name == "cursor", guardSeen, "Only this session's reported hook outcomes or recorded guard decisions count. This does not prove every tool call is guarded.", now)
		row.Trace = coveragePath(supportsTrace(root.Name), fact.TraceLastSeen, "Attributed tool, turn or model activity in this session; a quiet session can be legitimate.", now)
		row.Payload = coveragePath(true, fact.PayloadLastSeen, "Session-level inspection is unverified without an attributed match. The proxy hit stream normally lacks session identity; review Egress for machine-level evidence. Other traffic may be uninspected.", now)
		if !st.ProxyEnabled {
			row.Payload.State = "off"
			row.Payload.Detail = "Proxy is off. Historical matches do not establish current inspection."
		}
		if row.SessionID == "" {
			for _, p := range []*CoveragePath{&row.Guard, &row.Trace, &row.Payload} {
				if p.Supported && p.State != "off" {
					p.State = "unattributed"
				}
				p.Detail = "No durable session matches this live process and start time. Coverage cannot be credited by agent name or PID alone."
			}
		}
		if c.stale {
			for _, p := range []*CoveragePath{&row.Guard, &row.Trace, &row.Payload} {
				p.State = "stale"
				p.Detail = "Coverage data could not be refreshed. Timestamps are last-known observations."
			}
		}
		cov.Sessions = append(cov.Sessions, row)
	}
}
