// Package hookhealth derives bounded, deterministic hook diagnoses. It never
// infers protection coverage, security roles or task progress from run totals.
package hookhealth

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

const Window = 30 * time.Minute
const RunLimit = 1000
const FindingLimit = 20
const RepeatThreshold = 3
const SlowMs = 2000
const LargeContextChars = 10000

type Finding struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Harness     string    `json:"harness"`
	Event       string    `json:"event"`
	Script      string    `json:"script,omitempty"`
	HandlerID   string    `json:"handler_id"`
	ConfigID    string    `json:"config_id,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	NextAction  string    `json:"next_action"`
	Limits      []string  `json:"limits"`
	Count       int       `json:"count"`
	FirstAt     time.Time `json:"first_at"`
	LastAt      time.Time `json:"last_at"`
	NeedsAction bool      `json:"needs_action"`
}

type Assessment struct {
	Available        bool      `json:"available"`
	Since            time.Time `json:"since"`
	Until            time.Time `json:"until"`
	ObservedRuns     int       `json:"observed_runs"`
	UnattributedRuns int       `json:"unattributed_runs"`
	Truncated        bool      `json:"truncated"`
	Findings         []Finding `json:"findings"`
}

func Assess(runs []hookrun.Record, now time.Time, truncated bool) Assessment {
	a := Assessment{Available: true, Since: now.Add(-Window), Until: now, Truncated: truncated, Findings: []Finding{}}
	groups := map[string][]hookrun.Record{}
	for _, r := range runs {
		if r.TS.Before(a.Since) || r.TS.After(now) {
			continue
		}
		a.ObservedRuns++
		if r.Evidence == nil || r.Evidence.HandlerID == "" {
			a.UnattributedRuns++
			continue
		}
		key := strings.Join([]string{r.SessionID, r.Harness, r.Event, r.Evidence.HandlerID}, "\x00")
		groups[key] = append(groups[key], r)
	}
	for key, rs := range groups {
		// IDs only make output deterministic. They never establish chronology
		// within a tied timestamp; consecutiveCount handles those buckets.
		sort.Slice(rs, func(i, j int) bool {
			if !rs[i].TS.Equal(rs[j].TS) {
				return rs[i].TS.Before(rs[j].TS)
			}
			return rs[i].ID < rs[j].ID
		})
		last := rs[len(rs)-1]
		revisionRuns := consecutiveCount(rs, func(r hookrun.Record) bool { return r.Evidence.ConfigID == last.Evidence.ConfigID })
		if revisionRuns == 0 {
			continue
		}
		rs = rs[len(rs)-revisionRuns:]
		key += "\x00" + last.Evidence.ConfigID
		n := consecutiveCount(rs, func(r hookrun.Record) bool { return r.Status == "error" })
		if n >= RepeatThreshold {
			f := newFinding(key, "execution-errors", rs[len(rs)-n:], true)
			f.Title = "Hook repeatedly failed"
			f.Detail = fmt.Sprintf("%d consecutive observed execution errors for this handler.", n)
			f.NextAction = "Check this handler's local diagnostics and configuration, repair the failing dependency or command, then retry."
			switch last.Evidence.ReasonCode {
			case "timeout":
				f.NextAction = "Check whether this handler is waiting on input, a network request or another process. Bound that work and retry the hook."
			case "dependency-unavailable":
				f.NextAction = "Restore the executable or service required by this handler, confirm its configured location, then retry the hook."
			case "invalid-output":
				f.NextAction = "Check this handler's output against the harness hook protocol, correct the response format, then retry the hook."
			case "permission-denied":
				f.NextAction = "Check the handler's executable and file permissions. Grant only the access it requires, then retry the hook."
			}
			if last.Evidence.ReasonCode != "" {
				f.Detail += " Reported reason: " + last.Evidence.ReasonCode + "."
			}
			if last.Evidence.ControlRole == "security" {
				f.Title = "Security hook repeatedly failed"
				f.Detail += " The forwarding host identifies this handler as a security control."
			}
			switch last.Evidence.ActionOutcome {
			case "stopped":
				f.Detail += " The host reports that the associated action was stopped."
			case "proceeded":
				f.Detail += " The host reports that the associated action proceeded."
			default:
				f.Limits = append(f.Limits, "The associated action's outcome is unknown.")
			}
			a.Findings = append(a.Findings, f)
		}
		// Different actions must never be combined into a purported retry loop.
		ops := map[string][]hookrun.Record{}
		for _, r := range rs {
			if r.Evidence.OperationID != "" {
				ops[r.Evidence.OperationID] = append(ops[r.Evidence.OperationID], r)
			}
		}
		for op, os := range ops {
			n := consecutiveCount(os, func(r hookrun.Record) bool { return r.Status == "block" || r.Status == "deny" })
			if n < RepeatThreshold {
				continue
			}
			f := newFinding(key+"\x00"+op, "repeated-blocks", os[len(os)-n:], false)
			f.OperationID = op
			f.Title = "Repeated hook blocks for one action"
			f.Detail = fmt.Sprintf("%d observed block decisions for the same host-correlated action.", n)
			f.NextAction = "Inspect the blocked action and the handler's rule. Adjust the request if appropriate; retain the protection while reviewing policy."
			f.Limits = append(f.Limits, "Block decisions can be expected protection or validation retries; overall task progress is unknown.")
			a.Findings = append(a.Findings, f)
		}
		// Advisories use the latest consecutive eligible samples. Unknown metrics,
		// background work, config changes and recovery end the pattern.
		for _, kind := range []string{"slow-foreground", "large-context"} {
			n := consecutiveCount(rs, func(r hookrun.Record) bool {
				e := r.Evidence
				eligible := r.Status == "ok" || r.Status == "inject" || r.Status == "block" || r.Status == "deny"
				if kind == "slow-foreground" {
					eligible = eligible && e.DurationKnown && e.ExecutionMode == "foreground" && r.DurationMs >= SlowMs
				} else {
					eligible = eligible && e.ContextChars != nil && *e.ContextChars >= LargeContextChars
				}
				return eligible
			})
			if n < RepeatThreshold {
				continue
			}
			f := newFinding(key, kind, rs[len(rs)-n:], false)
			if kind == "slow-foreground" {
				f.Title = "Hook repeatedly takes at least two seconds"
				f.Detail = fmt.Sprintf("%d consecutive measured foreground runs took at least %d ms each.", n, SlowMs)
				f.NextAction = "Review this handler's work and invocation conditions; reduce unnecessary work or use background execution if the hook's semantics allow it."
				f.Limits = append(f.Limits, "Foreground callback durations are not a measurement of total task delay; callbacks may overlap.")
			} else {
				f.Title = "Hook repeatedly contributes substantial context"
				f.Detail = fmt.Sprintf("%d consecutive observed runs each contributed at least %d context characters.", n, LargeContextChars)
				f.NextAction = "Review this handler's context scope and invocation conditions; include only the context needed for the action."
				f.Limits = append(f.Limits, "Character counts do not establish token cost, duplicate content or malicious injection.")
			}
			a.Findings = append(a.Findings, f)
		}
	}
	sort.Slice(a.Findings, func(i, j int) bool {
		x, y := a.Findings[i], a.Findings[j]
		if x.NeedsAction != y.NeedsAction {
			return x.NeedsAction
		}
		if !x.LastAt.Equal(y.LastAt) {
			return x.LastAt.After(y.LastAt)
		}
		return x.ID < y.ID
	})
	if len(a.Findings) > FindingLimit {
		a.Findings = a.Findings[:FindingLimit]
		a.Truncated = true
	}
	return a
}

// A timestamp bucket contributes only if every run in it qualifies. Otherwise
// an ineligible peer could have occurred last, regardless of execution ID.
func consecutiveCount(rs []hookrun.Record, eligible func(hookrun.Record) bool) int {
	n := 0
	for end := len(rs); end > 0; {
		start := end - 1
		for start > 0 && rs[start-1].TS.Equal(rs[end-1].TS) {
			start--
		}
		for i := start; i < end; i++ {
			if !eligible(rs[i]) {
				return n
			}
		}
		n += end - start
		end = start
	}
	return n
}

func newFinding(key, kind string, rs []hookrun.Record, action bool) Finding {
	r := rs[len(rs)-1]
	id := sha256.Sum256([]byte(key + "\x00" + kind))
	limits := []string{"Based only on recorded completions in the recent window; this does not establish protection coverage."}
	if r.Evidence.ConfigID == "" {
		limits = append(limits, "Configuration revision was not supplied by the host.")
	}
	return Finding{ID: fmt.Sprintf("hook:%x", id[:16]), Kind: kind, Harness: r.Harness, Event: r.Event, Script: r.Script, HandlerID: r.Evidence.HandlerID, ConfigID: r.Evidence.ConfigID, Count: len(rs), FirstAt: rs[0].TS, LastAt: r.TS, NeedsAction: action, Limits: limits}
}
