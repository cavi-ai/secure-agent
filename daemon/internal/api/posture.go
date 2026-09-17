package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
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

// handlePosture serves the operator headline. The computation lives in
// computePosture so the fleet heartbeat can ship the exact same headline the
// local UIs render — one derivation, three consumers (console, menubar,
// collector).
func (a *API) handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.computePosture())
}

// CurrentPosture exposes the computed headline to non-HTTP consumers (the
// fleet heartbeat loop).
func (a *API) CurrentPosture() Posture { return a.computePosture() }

// computePosture derives the operator headline from live status + stores.
// Deliberately derived, not persisted: posture is a view over state, never a
// second source of truth.
func (a *API) computePosture() Posture {
	st := a.statusFn()
	posture := Posture{
		Items:     []PostureItem{},
		Generated: time.Now().UTC().Format(time.RFC3339Nano),
		Connected: st.Running,
	}

	// 1. Critical/high flags — the security signal. Unacted only: a flag the
	// operator already reviewed/dismissed must not keep demanding attention.
	for _, f := range a.store.QueryFlags(store.FlagFilter{MinSeverity: 2, Limit: 25, Unacted: true}) {
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
			posture.Items = append(posture.Items, PostureItem{
				Kind: "collector_down", ID: c.Name,
				Title:    humanCollectorTitle(c.Name, c.Abandoned),
				Severity: 2,
				Detail:   humanCollectorDetail(c.Name, c.LastError),
			})
		}
	}

	// 3b. Silent collectors — running but producing nothing while agents are
	// active. Liveness is not coverage: the worst failure mode a monitor can
	// have is reporting green while blind (both audited live: the eslogger
	// spool untouched for days, zero hook events for 17h, all "healthy").
	if st.ActiveAgents > 0 {
		for _, item := range silentCollectorItems(st) {
			posture.Items = append(posture.Items, item)
		}
		if item := harnessUncoveredItem(a.store, st); item != nil {
			posture.Items = append(posture.Items, *item)
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

	// 5. Aging incidents — an open incident older than 72h is a queue item
	// going stale, not a finding. Resolve it or acknowledge it.
	for _, inc := range a.store.RecentIncidents(25) {
		wf, _ := a.store.IncidentStatus(inc.ID)
		if wf.Status == "resolved" {
			continue
		}
		if time.Since(inc.Timestamp) > 72*time.Hour {
			posture.Items = append(posture.Items, PostureItem{
				Kind: "incident", ID: inc.ID,
				Title:    "Aging incident: " + humanFlagTitle(inc.Rule),
				Severity: 1,
				Detail:   "open more than 3 days — resolve or acknowledge",
			})
		}
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

	return posture
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
	n := len(items)
	noun := "items need"
	if n == 1 {
		noun = "item needs"
	}
	return fmt.Sprintf("%d %s you — first: %s.", n, noun, top.Title)
}

// collectorSilenceWindows: how long a producer collector may publish nothing
// while agents are active before posture calls it blind. Netsampler is
// excluded: an idle-but-working agent legitimately opens no sockets for long
// stretches, so its silence is ambiguous. File and transcript telemetry are
// not ambiguous — an active harness touches files constantly.
var collectorSilenceWindows = map[string]time.Duration{
	"eslogger":   30 * time.Minute,
	"transcript": 30 * time.Minute,
}

// collectorBootGrace suppresses never-produced items right after daemon
// start: collectors need a few minutes to see their first event.
const collectorBootGrace = 10 * time.Minute

// silentCollectorItems flags running collectors that have produced nothing
// recent (or nothing at all past the boot grace) while agents are active.
func silentCollectorItems(st Status) []PostureItem {
	var items []PostureItem
	uptime, _ := time.ParseDuration(st.Uptime)
	for _, c := range st.Collectors {
		if !c.Running || c.Abandoned {
			continue
		}
		window, watched := collectorSilenceWindows[c.Name]
		if !watched {
			continue
		}
		if c.LastProduced == "" {
			if uptime >= collectorBootGrace {
				items = append(items, PostureItem{
					Kind: "collector_silent", ID: c.Name,
					Title:    humanCollectorSilentTitle(c.Name) + " is producing nothing",
					Severity: 2,
					Detail:   "collector is running but has published no events since daemon start — telemetry source may be dead",
				})
			}
			continue
		}
		last, err := time.Parse(time.RFC3339, c.LastProduced)
		if err != nil {
			continue
		}
		if time.Since(last) > window {
			items = append(items, PostureItem{
				Kind: "collector_silent", ID: c.Name,
				Title:    humanCollectorSilentTitle(c.Name) + " went quiet",
				Severity: 2,
				Detail:   "no events for more than " + window.String() + " while agents are active — check the telemetry source",
			})
		}
	}
	return items
}

func humanCollectorSilentTitle(name string) string {
	switch name {
	case "eslogger":
		return "File monitoring"
	case "transcript":
		return "Transcript scanning"
	}
	return "Monitor " + name
}

// harnessUncoveredItem flags the audited failure mode: agent processes are
// running but no harness hook or transcript event has landed in 24h — the
// hooks are not registered (or every harness is uncovered).
func harnessUncoveredItem(st *store.Store, status Status) *PostureItem {
	if st == nil {
		return nil
	}
	since := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	for _, kind := range []event.Kind{event.KindTranscriptHit, event.KindPluginAction} {
		k := int(kind)
		if len(st.QueryEvents(store.EventFilter{Kind: &k, Since: since, Limit: 1})) > 0 {
			return nil
		}
	}
	return &PostureItem{
		Kind: "harness_uncovered", ID: "harness-hooks",
		Title:    "No harness hook activity in 24h",
		Severity: 2,
		Detail:   fmt.Sprintf("%d agent(s) running but hooks never fired — hooks may not be registered (run Setup)", status.ActiveAgents),
	}
}

// humanCollectorTitle maps collector process names to operator language —
// "Monitor eslogger is abandoned" is jargon; "File monitoring is off" is not.
func humanCollectorTitle(name string, abandoned bool) string {
	what := map[string]string{
		"eslogger":    "File monitoring",
		"netsampler":  "Network sampling",
		"transcript":  "Transcript scanning",
		"proxyserver": "Egress inspection",
		"advisor":     "Local advisor",
	}[name]
	if what == "" {
		what = "Monitor " + name
	}
	if abandoned {
		return what + " keeps stopping"
	}
	return what + " is off"
}

// humanCollectorDetail pairs the raw error with the likely fix.
func humanCollectorDetail(name, lastErr string) string {
	var hint string
	switch name {
	case "eslogger":
		// eslogger crash-loops almost always mean Full Disk Access is missing.
		hint = "usually missing Full Disk Access — open Setup & Permissions in the menu bar"
	case "netsampler":
		hint = "restart Secure Agent from the menu bar"
	case "proxyserver":
		hint = "check whether another process holds the proxy port"
	case "transcript":
		hint = "restart Secure Agent from the menu bar"
	case "advisor":
		hint = "check the local model server (default 127.0.0.1:8080)"
	}
	if lastErr == "" {
		return hint
	}
	if hint == "" {
		return lastErr
	}
	return hint + " · " + lastErr
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
	case "keychain-security-cli":
		return "Agent ran the macOS keychain tool"
	case "tcc-tamper":
		return "Agent modified macOS privacy permissions (TCC)"
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
