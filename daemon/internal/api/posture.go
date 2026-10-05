package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// PostureItem is one thing the operator may need to act on.
type PostureItem struct {
	Kind      string `json:"kind"` // flag | incident | guard_pending | recurring_egress | resource_pressure | coverage kinds
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  int    `json:"severity"` // 3 critical, 2 high, 1 medium, 0 info
	Detail    string `json:"detail,omitempty"`
	Timestamp string `json:"ts,omitempty"`
}

// Posture is the single headline answer: "do I need to look at this machine,
// and what is the one thing to look at first?" Every UI (console, menubar,
// fleet collector) renders from this instead of re-deriving it from raw lists.
//
// Invariant: every pending decision in Items appears in exactly one Group,
// and group item counts sum to NeedsYou (= len(Items)). CoverageItems are
// monitoring gaps and informational uninspected egress, counted separately;
// only a gap moves State off all-clear.
type Posture struct {
	State         string        `json:"state"` // all-clear | attention | critical
	NeedsYou      int           `json:"needs_you"`
	CoverageCount int           `json:"coverage_count"`
	Summary       string        `json:"summary"`
	Items         []PostureItem `json:"items"`
	CoverageItems []PostureItem `json:"coverage_items"`
	// Groups is the session-grouped attention queue every surface renders;
	// agent-less items sit in the "machine" group.
	Groups    []AttentionGroup `json:"groups,omitempty"`
	Generated string           `json:"generated"`
	Connected bool             `json:"connected"`
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

// PublishPostureIfChanged recomputes the headline and pushes a posture delta
// only when it actually changed — HTTP mutations and the drain loop call
// this after flag/incident/guard changes; per-event calls would recompute on socket
// churn, so dedupe happens here, not there.
func (a *API) PublishPostureIfChanged() {
	if a.deltaHub == nil {
		return
	}
	p := a.computePosture()
	a.lastPostureMu.Lock()
	changed := p.State != a.lastPostureState || p.NeedsYou != a.lastPostureCount || p.CoverageCount != a.lastPostureCoverage
	if changed {
		a.lastPostureState = p.State
		a.lastPostureCount = p.NeedsYou
		a.lastPostureCoverage = p.CoverageCount
	}
	a.lastPostureMu.Unlock()
	if changed {
		a.deltaHub.Publish(Delta{Type: "posture", Data: p})
	}
}

// computePosture derives the operator headline from live status + stores.
// Deliberately derived, not persisted: posture is a view over state, never a
// second source of truth.
func (a *API) computePosture() Posture {
	st := a.evidenceStatus(a.statusFn())
	posture := Posture{
		Generated: time.Now().UTC().Format(time.RFC3339Nano),
		Connected: st.Running,
	}
	posture.Items, posture.Groups = a.attentionQueue(st)
	posture.NeedsYou = len(posture.Items)
	posture.CoverageItems = a.coverageItems(st)
	posture.CoverageCount = len(posture.CoverageItems)
	switch {
	case posture.NeedsYou == 0 && !hasMonitoringGap(posture.CoverageItems):
		posture.State = "all-clear"
		posture.Summary = "All clear — agents monitored, no action needed."
	case posture.NeedsYou == 0:
		posture.State = "attention"
		posture.Summary = "No decisions pending. Monitoring coverage needs attention."
	case hasCritical(posture.Items):
		posture.State = "critical"
		posture.Summary = criticalSummary(posture.Items)
	default:
		posture.State = "attention"
		posture.Summary = attentionSummary(posture.Items)
	}

	return posture
}

func (a *API) coverageItems(st Status) []PostureItem {
	items := a.machineAttentionItems(st)
	if st.UninspectedEgress > 0 {
		items = append(items, PostureItem{
			Kind: "uninspected_egress", ID: "uninspected-egress",
			Title:    uninspectedTitle(st.UninspectedEgress),
			Severity: 1,
			Detail:   "Review endpoints that bypassed inspection in Egress.",
		})
	}
	return items
}

// hasMonitoringGap reports whether coverage holds a gap the operator must fix
// (a collector down or silent, a hook missing, a harness unseen). Uninspected
// egress is a coverage note, not a gap: alone it leaves posture all-clear.
func hasMonitoringGap(items []PostureItem) bool {
	for _, it := range items {
		if it.Kind != "uninspected_egress" {
			return true
		}
	}
	return false
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

// firstEvidence is the first evidence line, rendered for text display.
func firstEvidence(ev []model.EvidenceItem) string {
	if len(ev) == 0 {
		return ""
	}
	return ev[0].String()
}

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
// For the eslogger tailer the goroutine's heartbeat is not the whole story:
// the WRITER is the root LaunchDaemon, so its real launchd state and spool
// freshness are probed too — a crash-looping writer (exit 1 every respawn)
// must read as blind even while the tailer itself runs green.
func silentCollectorItems(st Status) []PostureItem {
	var items []PostureItem
	uptime, _ := time.ParseDuration(st.Uptime)
	// Probe the root service once per posture pass; only meaningful when
	// the daemon tails the spool (an eslogger collector row that came from
	// a direct root eslogger child has no external service).
	for _, c := range st.Collectors {
		if c.Name == "eslogger" && c.Running && !c.Abandoned && st.ESService != nil {
			svcItems := esServiceItems(*st.ESService)
			items = append(items, svcItems...)
			// The spool-based probe supersedes the tailer heartbeat when it
			// reports a failure: both would emit collector_silent under the
			// same id, double-counting one blind spot. A healthy probe with
			// a still-silent tailer keeps the generic check.
			if len(svcItems) > 0 {
				continue
			}
		}
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

// esServiceItems turns one root-service probe into posture items. The probe
// is best-effort: launchctl errors are already folded into the state string.
// A flooding writer supersedes every other eslogger item: the tailer and the
// root service can both read healthy while the writer drowns them in
// garbage, and that is the failure the operator needs to see first. Events
// arriving long after they happened (esServiceLagging) come next: the spool
// is written and the tailer keeps up, yet every file flag and resource
// episode sees the activity that late. A sustained burst of otherwise-valid
// lines the tailer cannot keep up with (esServiceBehind) is a lesser item:
// the writer is fine, the reader is behind.
func esServiceItems(s collect.ESServiceSnapshot) []PostureItem {
	if esServiceFlooding(s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring writer is flooding",
			Severity: 2,
			Detail:   esFloodingDetail(s),
		}}
	}
	if esServiceLagging(s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring is running late",
			Severity: 2,
			Detail:   esLaggingDetail(s),
		}}
	}
	if esServiceBehind(s) {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring is falling behind",
			Severity: 1,
			Detail:   esBehindDetail(s),
		}}
	}
	// A spool exists, so file telemetry was on; the service is gone.
	if s.State == "not-loaded" && !s.SpoolMtime.IsZero() {
		return []PostureItem{{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring is off",
			Severity: 2,
			Detail: "the file telemetry helper is not loaded — enable it in Setup & Permissions → File Telemetry, " +
				"then approve Secure Agent in Login Items and Full Disk Access",
		}}
	}
	var items []PostureItem
	if esServiceFailing(s.State) {
		next := "check /var/log/secure-agent-esd.log"
		if esServiceRefused(s.State) {
			next = esReregisterHint + ", then " + next
		}
		items = append(items, PostureItem{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring service is failing",
			Severity: 2,
			Detail:   "root ES collector service state: " + s.State + " — spool " + s.SpoolState() + " — " + next,
		})
	} else if time.Since(s.SpoolMtime) > 30*time.Minute {
		detail := "root ES collector reports " + s.State + " but the spool " + s.SpoolState() + " — file telemetry may be blind"
		// An ad-hoc signed build's privacy grant is bound to that build: a
		// collector binary installed after the last spool write lost it.
		if esServiceRunning(s.State) && !s.SpoolMtime.IsZero() && s.HelperMtime.After(s.SpoolMtime) {
			detail = "root ES collector reports running but the spool " + s.SpoolState() +
				" — the helper binary was replaced after the last write; grant Full Disk Access again for Secure Agent"
		}
		items = append(items, PostureItem{
			Kind: "collector_silent", ID: "eslogger",
			Title:    "File monitoring service is not writing",
			Severity: 2,
			Detail:   detail,
		})
	}
	return items
}

// esFloodFreshWindow: a flood verdict needs a spool written this recently.
const esFloodFreshWindow = 2 * time.Minute

// esServiceFailing reports a root ES service state that means the writer is
// crash-looping (spawn scheduled) or has exited. A running service whose
// state carries an earlier non-zero exit ("running (last exit 1)") was
// restarted and is up; the spool's age judges whether it writes.
func esServiceFailing(state string) bool {
	if esServiceRunning(state) {
		return false
	}
	return strings.Contains(state, "spawn") || strings.Contains(state, "exit")
}

// esServiceRefused reports a root ES service launchd will not bring up: last
// exit 78 (EX_CONFIG, launchd refusing the spawn; the helper never exits 78)
// while not running, or spawn scheduled after a nonzero exit. The menu bar
// Doctor's Re-register binds the job to the installed build again.
func esServiceRefused(state string) bool {
	if esServiceRunning(state) {
		return false
	}
	// parseLaunchctlState notes only nonzero exits: " (last exit 78: EX_CONFIG)".
	_, note, ok := strings.Cut(state, " (last exit ")
	if !ok {
		return false
	}
	head, _, _ := strings.Cut(strings.TrimSuffix(note, ")"), ":")
	code, err := strconv.Atoi(head)
	if err != nil || code == 0 {
		return false
	}
	return code == esExConfig || strings.HasPrefix(state, "spawn scheduled")
}

// esExConfig is sysexits' EX_CONFIG, launchd's code for a job it could not spawn.
const esExConfig = 78

// esReregisterHint is the action both the posture and doctor details name
// for a refused service.
const esReregisterHint = "Re-register it from Run Doctor… in the menu bar"

// esServiceRunning reports a running root ES service, with or without an
// earlier exit noted after the state.
func esServiceRunning(state string) bool {
	return state == "running" || strings.HasPrefix(state, "running (")
}

// esServiceFlooding reports a writer producing mostly-unparseable lines —
// garbage, not a burst the tailer merely fell behind on. Skipping alone
// (s.Flooding) no longer counts: SpoolStats.Lines counts only lines the
// scanner read, so UnparsedShare over half means those READ lines were
// mostly garbage, whatever the tailer skipped in bulk notwithstanding.
func esServiceFlooding(s collect.ESServiceSnapshot) bool {
	// Garbage in a spool nobody writes any more is leftover, not a flood:
	// the last drain's verdict counts only while the writer is still active.
	if s.SpoolMtime.IsZero() || time.Since(s.SpoolMtime) > esFloodFreshWindow {
		return false
	}
	return s.UnparsedShare > 0.5
}

// esFloodingDetail is the shared wording for the flooding (garbage) failure:
// posture and doctor report the same facts.
func esFloodingDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("%.0f%% of lines in the last drain did not parse — the writer is producing garbage",
		s.UnparsedShare*100)
}

// esLagWindow: file events delivered later than this after they happened
// are too late for a flag or a resource episode to use. The root collector
// restarts eslogger after 30 s past 60 s, so a lag this long means it has not.
const esLagWindow = 2 * time.Minute

// esServiceLagging reports file events reaching the daemon esLagWindow or
// more after they happened, while the writer is still writing.
func esServiceLagging(s collect.ESServiceSnapshot) bool {
	if s.SpoolMtime.IsZero() || time.Since(s.SpoolMtime) > esFloodFreshWindow || s.NewestEventAt == nil {
		return false
	}
	return time.Duration(s.LagSeconds)*time.Second >= esLagWindow
}

// esLaggingDetail is the shared wording for the late-delivery failure:
// posture and doctor report the same facts.
func esLaggingDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("the newest file event delivered happened at %s, %s before it arrived — file flags and resource episodes see file activity that late",
		s.NewestEventAt.Local().Format("15:04:05"), time.Duration(s.LagSeconds)*time.Second)
}

// esBehindWindow: a skip shorter than this is normal load on a healthy
// writer, not a reader that is stuck falling behind.
const esBehindWindow = 60 * time.Second

// esServiceBehind reports a healthy writer (not garbage) whose valid-line
// bursts have made the tailer skip past its per-tick budget for longer than
// esBehindWindow — the reader is behind, not broken. Garbage supersedes this:
// esServiceFlooding is checked first by callers and takes priority.
func esServiceBehind(s collect.ESServiceSnapshot) bool {
	if s.SpoolMtime.IsZero() || time.Since(s.SpoolMtime) > esFloodFreshWindow {
		return false
	}
	if esServiceFlooding(s) {
		return false
	}
	return s.Flooding && s.FloodingSince != nil && time.Since(*s.FloodingSince) > esBehindWindow
}

// esBehindDetail is the shared wording for the falling-behind failure:
// posture and doctor report the same facts. spoolDrainBudget (4 MiB per
// 200ms tick, in collect/spool.go) is a fixed 20 MB/s reader limit.
func esBehindDetail(s collect.ESServiceSnapshot) string {
	return fmt.Sprintf("skipping since %s, last drain skipped %.1f MB — the reader's limit is 20 MB/s",
		s.FloodingSince.Local().Format("15:04"), float64(s.BytesSkipped)/(1<<20))
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

// hookActivityWindow is how far back hook evidence counts as activity.
const hookActivityWindow = 24 * time.Hour

// guardHookUnregisteredItem reports that the Claude Code guard hook is not
// registered in ~/.claude/settings.json, so the PreToolUse/PostToolUse guard
// never runs for that harness. This is a distinct failure from "the
// transcript scanner is silent": an agent can be active and traced while the
// guard is unregistered. Registered-but-broken is caught by the hook
// self-test; this catches never-registered.
func guardHookUnregisteredItem(status Status) *PostureItem {
	if !activeHarness(status, "claude") {
		return nil
	}
	settings, err := claudeSettingsPath()
	if err != nil {
		return nil
	}
	if !claudeHookRegistered(settings) {
		return &PostureItem{
			Kind: "guard_hook_unregistered", ID: "claude-hook",
			Title:    "Claude Code guard hook is not registered",
			Severity: 2,
			Detail:   "~/.claude/settings.json has no guard hook, so the PreToolUse guard never runs — install it from Setup & Permissions",
		}
	}
	return nil
}

// claudeSettingsPath is the user-level Claude Code settings file the guard
// hook registers in.
func claudeSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// claudeHookRegistered reports whether settings.json registers the guard hook
// for both PreToolUse and PostToolUse. A missing/unreadable file is not
// registered.
func claudeHookRegistered(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var root struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(data, &root) != nil {
		return false
	}
	guard := func(eventName string) bool {
		for _, group := range root.Hooks[eventName] {
			for _, h := range group.Hooks {
				if strings.Contains(h.Command, ".claude/hooks/secret_guard.py") {
					return true
				}
			}
		}
		return false
	}
	return guard("PreToolUse") && guard("PostToolUse")
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
		return "Sensitive file read near an outside connection"
	case "keychain-access":
		return "Agent touched the keychain"
	case "keychain-security-cli":
		return "Agent ran the macOS keychain tool"
	case "tcc-tamper":
		return "Agent modified macOS privacy permissions (TCC)"
	case "proxy-prompt-injection":
		return "Prompt injection in a response"
	case "secret-in-transcript":
		return "Secret appeared in an agent transcript"
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
