package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// PostureItem is one thing the operator may need to act on.
type PostureItem struct {
	Kind      string `json:"kind"` // flag | incident | guard_pending | collector_down | uninspected_egress
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  int    `json:"severity"` // 3 critical, 2 high, 1 medium, 0 info
	Detail    string `json:"detail,omitempty"`
	Timestamp string `json:"ts,omitempty"`
}

// Posture is the single headline answer: "do I need to look at this machine,
// and what is the one thing to look at first?" Every UI (console, menubar,
// fleet collector) renders from this instead of re-deriving it from raw lists.
type Posture struct {
	State     string        `json:"state"` // all-clear | attention | critical
	NeedsYou  int           `json:"needs_you"`
	Summary   string        `json:"summary"`
	Items     []PostureItem `json:"items"`
	Generated string        `json:"generated"`
	Connected bool          `json:"connected"`
}

// handlePosture computes the operator headline from live status + stores.
// Deliberately derived, not persisted: posture is a view over state, never a
// second source of truth.
func (a *API) handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := a.statusFn()
	posture := Posture{
		Items:     []PostureItem{},
		Generated: time.Now().UTC().Format(time.RFC3339Nano),
		Connected: st.Running,
	}

	// 1. Critical/high flags — the security signal.
	for _, f := range a.store.QueryFlags(store.FlagFilter{MinSeverity: 2, Limit: 25}) {
		if isRecent(f.TS, 24*time.Hour) {
			posture.Items = append(posture.Items, PostureItem{
				Kind: "flag", ID: f.ID,
				Title:     humanFlagTitle(f.Rule),
				Severity:  f.Severity,
				Detail:    firstEvidence(f.Evidence),
				Timestamp: f.TS.UTC().Format(time.RFC3339),
			})
		}
	}

	// 2. Guard prompts waiting — the operator is actively being asked.
	if a.guardBroker != nil {
		for _, p := range a.guardBroker.Pending() {
			posture.Items = append(posture.Items, PostureItem{
				Kind: "guard_pending", ID: p.ID,
				Title:     p.Agent + " wants " + humanPath(p.Path),
				Severity:  1,
				Detail:    "Rule: " + p.RuleID,
				Timestamp: p.TS,
			})
		}
	}

	// 3. Dead collectors — a monitor that stopped is a blind spot, not a detail.
	for _, c := range st.Collectors {
		if !c.Running || c.Abandoned {
			state := "down"
			if c.Abandoned {
				state = "abandoned"
			}
			posture.Items = append(posture.Items, PostureItem{
				Kind: "collector_down", ID: c.Name,
				Title:    "Monitor " + c.Name + " is " + state,
				Severity: 2,
				Detail:   c.LastError,
			})
		}
	}

	// 4. Uninspected egress — visibility gap made explicit.
	if st.UninspectedEgress > 0 {
		posture.Items = append(posture.Items, PostureItem{
			Kind: "uninspected_egress", ID: "uninspected-egress",
			Title:    uninspectedTitle(st.UninspectedEgress),
			Severity: 1,
		})
	}

	posture.NeedsYou = len(posture.Items)
	switch {
	case posture.NeedsYou == 0:
		posture.State = "all-clear"
		posture.Summary = "All clear — agents monitored, no action needed."
	case hasCritical(posture.Items):
		posture.State = "critical"
		posture.Summary = criticalSummary(posture.Items)
	default:
		posture.State = "attention"
		posture.Summary = attentionSummary(posture.Items)
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, posture)
}

func hasCritical(items []PostureItem) bool {
	for _, it := range items {
		if it.Severity >= 3 {
			return true
		}
	}
	return false
}

func isRecent(ts time.Time, window time.Duration) bool {
	if ts.IsZero() {
		return false
	}
	return time.Since(ts) <= window
}

func firstNonEmpty(strs []string) string {
	for _, s := range strs {
		if s != "" {
			return s
		}
	}
	return ""
}

// humanPath shortens an absolute path to its tail for a headline.
func humanPath(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}

// firstEvidence is firstNonEmpty for a flag's evidence list.
func firstEvidence(ev []string) string { return firstNonEmpty(ev) }

// criticalSummary picks the highest-severity item as the one-line headline.
func criticalSummary(items []PostureItem) string {
	for _, it := range items {
		if it.Severity >= 3 {
			return it.Title + " — act now."
		}
	}
	return attentionSummary(items)
}

// attentionSummary names the count and the most severe non-critical item.
func attentionSummary(items []PostureItem) string {
	top := items[0]
	for _, it := range items[1:] {
		if it.Severity > top.Severity {
			top = it
		}
	}
	return fmt.Sprintf("%d item(s) need you — first: %s.", len(items), top.Title)
}

// humanFlagTitle maps rule ids to operator language (mirrors the menubar's
// NotificationManager titles; kept in sync manually until a shared table).
func humanFlagTitle(rule string) string {
	switch rule {
	case "proxy-secret-leak":
		return "Secret leaving in agent traffic"
	case "sensitive-read-then-connect":
		return "Agent read a secret, then connected out"
	case "keychain-access":
		return "Agent touched the keychain"
	case "proxy-prompt-injection":
		return "Prompt injection in a response"
	default:
		return rule
	}
}

func uninspectedTitle(n int) string {
	if n == 1 {
		return "1 connection bypassed the egress firewall"
	}
	return fmt.Sprintf("%d connections bypassed the egress firewall", n)
}
