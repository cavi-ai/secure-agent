package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// DoctorCheck is one self-check verdict. State is pass, fail or skip; Fix is
// a one-line remedy, set only on fail.
type DoctorCheck struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// DoctorSummary counts checks by state.
type DoctorSummary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// DoctorReport is the daemon's verdict on its own coverage: whether hooks,
// file telemetry, collectors and traces produce data, and whether stored
// sessions and events are attributed, paired, priced and retained. Grace is
// true inside the boot window, where steady-state checks skip.
type DoctorReport struct {
	GeneratedAt string        `json:"generated_at"`
	Version     string        `json:"version"`
	Uptime      string        `json:"uptime"`
	Grace       bool          `json:"grace"`
	Summary     DoctorSummary `json:"summary"`
	Checks      []DoctorCheck `json:"checks"` // fixed order; never nil
}

const (
	doctorPass = "pass"
	doctorFail = "fail"
	doctorSkip = "skip"

	doctorGraceDetail = "inside the 10-minute boot window"
	// doctorSpoolStale: a running root ES service whose spool is older than
	// this while agents are active is not writing.
	doctorSpoolStale = 10 * time.Minute
	// doctorEvictWindow: a kind at its row budget whose oldest row is younger
	// than this is being evicted inside one day.
	doctorEvictWindow = 24 * time.Hour
)

// doctorFacts is everything the checks read, gathered once per report so each
// check is a pure function of it.
type doctorFacts struct {
	now, boot time.Time
	grace     bool
	st        Status

	settingsKnown  bool
	hookRegistered bool
	hookUncovered  bool
	hookEvents24h  int

	sessionsTotal, sessionsNamed         int
	sessionsWithWorkspace, sessionsWRepo int
	sessionsLastHour                     int
	sessionsByHarness, traceByHarness    map[string]int
	seenByHarness                        map[string]int // transcript/hook sessions seen since boot

	dupePairs, idless int

	claudePriced, claudeUnpriced, allUnpriced, allCalls int

	retention []store.KindRetention

	hermes *collect.HermesStatus // nil when the collector is not wired
}

type doctorProbe struct {
	id, title, fix string
	run            func(f doctorFacts) (state, detail string)
}

// doctorProbes run in this order; the report lists them in it.
var doctorProbes = []doctorProbe{
	{"hook-registered", "Guard hook registered", "Run Setup → Harness hooks", checkHookRegistered},
	{"hook-active", "Guard hook active", "Run Setup → Harness hooks; the hook fires on every agent Bash tool call", checkHookActive},
	{"file-telemetry", "File telemetry", "System Settings → Privacy & Security → Full Disk Access → Secure Agent, or the Setup card — a flooding writer: Reinstall the file telemetry helper from the Setup card", checkFileTelemetry},
	{"collectors", "Collectors", "Restart Secure Agent from the menu bar; file monitoring that keeps stopping needs Full Disk Access (Setup)", checkCollectors},
	{"trace-coverage", "Trace coverage", "Restart Secure Agent; a harness that stays untraced has no transcript reader running", checkTraceCoverage},
	{"hermes", "Hermes Agent trace", "Point hermes_home at the Hermes root; a state.db this version cannot read needs a Secure Agent update", checkHermes},
	{"session-identity", "Session identity", "Check the Sessions tab for unnamed sessions; their processes were not recognized as a harness", checkSessionIdentity},
	{"session-repo", "Session repo attribution", "Restart Secure Agent to re-resolve repo and branch; a workspace outside a git checkout has no repo", checkSessionRepo},
	{"session-rate", "Session creation rate", "Check the Sessions tab for the harness creating stub sessions", checkSessionRate},
	{"tool-pairing", "Tool-call pairing", "Update Secure Agent so every harness adapter sends a call id; rows already stored stay unpaired", checkToolPairing},
	{"pricing", "Model-call pricing", "Update Secure Agent so its price table covers the Claude models in use", checkPricing},
	{"retention", "Event retention", "Find the process flooding these kinds in the Events tab; their rows are evicted inside a day", checkRetention},
	{"egress-routing", "Egress routing", "source agent-env.sh where agents launch, or Allow the endpoints in the Egress tab", checkEgressRouting},
	{"bus", "Event bus", "", checkBus},
}

// handleDoctor serves the daemon's self-check. Read-level.
//
//	GET /doctor
func (a *API) handleDoctor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.doctorReport(time.Now()))
}

func (a *API) doctorReport(now time.Time) DoctorReport {
	f := a.doctorFacts(now)
	rep := DoctorReport{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Version:     f.st.Version,
		Uptime:      f.st.Uptime,
		Grace:       f.grace,
		Checks:      make([]DoctorCheck, 0, len(doctorProbes)),
	}
	for _, p := range doctorProbes {
		state, detail := p.run(f)
		c := DoctorCheck{ID: p.id, Title: p.title, State: state, Detail: detail}
		switch state {
		case doctorPass:
			rep.Summary.Pass++
		case doctorFail:
			rep.Summary.Fail++
			c.Fix = p.fix
		default:
			rep.Summary.Skip++
		}
		rep.Checks = append(rep.Checks, c)
	}
	return rep
}

func (a *API) doctorFacts(now time.Time) doctorFacts {
	st := a.statusFn()
	uptime, _ := time.ParseDuration(st.Uptime)
	f := doctorFacts{
		now:   now,
		boot:  now.Add(-uptime),
		grace: uptime < collectorBootGrace,
		st:    st,
	}
	if path, err := claudeSettingsPath(); err == nil {
		f.settingsKnown = true
		f.hookRegistered = claudeHookRegistered(path)
	}
	f.hookUncovered = harnessUncoveredItem(a.store, st) != nil
	f.hookEvents24h = a.store.HookEventsSince(now.Add(-hookActivityWindow))
	f.sessionsTotal, f.sessionsNamed, f.sessionsWithWorkspace, f.sessionsWRepo = a.store.SessionIdentityStats(f.boot)
	f.sessionsLastHour = a.store.SessionsCreatedSince(now.Add(-time.Hour))
	f.sessionsByHarness = a.store.SessionsByHarness(f.boot)
	f.seenByHarness = a.store.SessionsSeenByHarness(f.boot)
	f.traceByHarness = a.store.TraceRowsByHarness(f.boot)
	f.dupePairs, f.idless = a.store.ToolCallStats(f.boot)
	f.claudePriced, f.claudeUnpriced, f.allUnpriced, f.allCalls = a.store.PricingStats()
	f.retention = a.store.RetentionReport()
	if a.hermes != nil {
		h := a.hermes()
		f.hermes = &h
	}
	return f
}

func pct(n, total int) int { return 100 * n / total }

func checkHookRegistered(f doctorFacts) (string, string) {
	switch {
	case !f.settingsKnown:
		return doctorSkip, "home directory unknown"
	case !f.hookRegistered:
		return doctorFail, "~/.claude/settings.json does not register the guard hook for PreToolUse and PostToolUse"
	}
	return doctorPass, "registered for PreToolUse and PostToolUse"
}

func checkHookActive(f doctorFacts) (string, string) {
	if f.st.ActiveAgents == 0 {
		return doctorSkip, "no agents running"
	}
	if f.hookUncovered {
		return doctorFail, fmt.Sprintf("%d agent(s) running, no hook event in 24h", f.st.ActiveAgents)
	}
	return doctorPass, fmt.Sprintf("%d hook events in 24h", f.hookEvents24h)
}

func checkFileTelemetry(f doctorFacts) (string, string) {
	es := f.st.ESService
	if es == nil {
		return doctorSkip, "not spool-based"
	}
	switch {
	case esServiceFlooding(*es):
		return doctorFail, esFloodingDetail(*es)
	case es.State == "not-loaded":
		return doctorFail, "root service not loaded"
	case esServiceFailing(es.State):
		return doctorFail, "root service state: " + es.State
	case es.State == "running" && f.st.ActiveAgents > 0 && !f.grace && f.now.Sub(es.SpoolMtime) > doctorSpoolStale:
		if es.SpoolMtime.IsZero() {
			return doctorFail, "service running but spool absent"
		}
		return doctorFail, fmt.Sprintf("service running but spool not written for %d min", int(f.now.Sub(es.SpoolMtime).Minutes()))
	}
	return doctorPass, es.State
}

func checkCollectors(f doctorFacts) (string, string) {
	if f.grace {
		return doctorSkip, doctorGraceDetail
	}
	var down, silent []string
	for _, c := range f.st.Collectors {
		switch {
		case c.Abandoned:
			down = append(down, c.Name+" (abandoned)")
		case !c.Running:
			down = append(down, c.Name+" (stopped)")
		}
	}
	// Silence only means blindness while agents are active (as in posture).
	if f.st.ActiveAgents > 0 {
		for _, it := range silentCollectorItems(f.st) {
			silent = append(silent, it.ID)
		}
	}
	var parts []string
	if len(down) > 0 {
		parts = append(parts, "down: "+strings.Join(down, ", "))
	}
	if len(silent) > 0 {
		parts = append(parts, "silent: "+strings.Join(silent, ", "))
	}
	// Polling collectors name their database, watermark and last poll
	// whatever the verdict.
	var polls string
	for _, c := range f.st.Collectors {
		if c.Source != "" {
			polls += fmt.Sprintf(" · %s %s @ %d polled %s", c.Name, c.Source, c.Watermark, c.LastPoll)
		}
	}
	if len(parts) > 0 {
		return doctorFail, strings.Join(parts, " · ") + polls
	}
	return doctorPass, fmt.Sprintf("%d collectors running", len(f.st.Collectors)) + polls
}

// checkHermes reports the Hermes Agent collector: not installed when no
// state.db exists under its root, else each database's watermark and the
// last poll, failing when a database could not be read.
func checkHermes(f doctorFacts) (string, string) {
	h := f.hermes
	switch {
	case h == nil:
		return doctorSkip, "not wired"
	case h.LastError != "":
		return doctorFail, h.LastError
	case len(h.DBs) == 0:
		return doctorSkip, fmt.Sprintf("not installed (no state.db under %s)", h.Root)
	}
	dbs := make([]string, len(h.DBs))
	for i, d := range h.DBs {
		dbs[i] = fmt.Sprintf("%s @ message %d", d.Path, d.Watermark)
	}
	return doctorPass, strings.Join(dbs, ", ") + " · polled " + h.LastPoll.UTC().Format(time.RFC3339)
}

// checkTraceCoverage counts the sessions SEEN since boot at transcript or hook
// confidence per harness (a conversation that started before boot and is
// active now counts) and fails for a harness with none of its trace rows.
func checkTraceCoverage(f doctorFacts) (string, string) {
	if f.grace {
		return doctorSkip, doctorGraceDetail
	}
	if len(f.seenByHarness) == 0 {
		return doctorSkip, "no sessions since boot"
	}
	var blind, traced []string
	for h, n := range f.seenByHarness {
		if f.traceByHarness[h] == 0 {
			blind = append(blind, h)
		} else {
			traced = append(traced, fmt.Sprintf("%s (%d sessions)", h, n))
		}
	}
	if len(blind) > 0 {
		sort.Strings(blind)
		return doctorFail, "sessions since boot but no trace rows: " + strings.Join(blind, ", ")
	}
	sort.Strings(traced)
	return doctorPass, fmt.Sprintf("%d harnesses traced: %s", len(traced), strings.Join(traced, ", "))
}

func checkSessionIdentity(f doctorFacts) (string, string) {
	if f.sessionsTotal == 0 {
		return doctorSkip, "no sessions"
	}
	detail := fmt.Sprintf("%d of %d sessions carry a harness (%d%%)", f.sessionsNamed, f.sessionsTotal, pct(f.sessionsNamed, f.sessionsTotal))
	if f.sessionsNamed*100 < f.sessionsTotal*80 {
		return doctorFail, detail + ", want ≥ 80%"
	}
	return doctorPass, detail
}

func checkSessionRepo(f doctorFacts) (string, string) {
	if f.grace {
		return doctorSkip, doctorGraceDetail
	}
	if f.sessionsWithWorkspace == 0 {
		named := 0
		for _, n := range f.sessionsByHarness {
			named += n
		}
		if named == 0 {
			return doctorSkip, "no named sessions since boot"
		}
		return doctorFail, fmt.Sprintf("0 of %d named sessions since boot carry a workspace — attribution drop", named)
	}
	detail := fmt.Sprintf("%d of %d sessions with a workspace since boot carry a repo (%d%%)",
		f.sessionsWRepo, f.sessionsWithWorkspace, pct(f.sessionsWRepo, f.sessionsWithWorkspace))
	if f.sessionsWRepo*100 < f.sessionsWithWorkspace*50 {
		return doctorFail, detail + ", want ≥ 50%"
	}
	return doctorPass, detail
}

func checkSessionRate(f doctorFacts) (string, string) {
	if f.grace {
		return doctorSkip, doctorGraceDetail
	}
	if f.st.ActiveAgents == 0 {
		return doctorSkip, "no agents running"
	}
	budget := 2*f.st.ActiveAgents + 10
	if f.sessionsLastHour > budget {
		return doctorFail, fmt.Sprintf("%d sessions created in the last hour, budget %d for %d agents", f.sessionsLastHour, budget, f.st.ActiveAgents)
	}
	return doctorPass, fmt.Sprintf("%d sessions created in the last hour (budget %d)", f.sessionsLastHour, budget)
}

func checkToolPairing(f doctorFacts) (string, string) {
	if f.dupePairs > 0 || f.idless > 0 {
		return doctorFail, fmt.Sprintf("%d duplicate (session, call_id) pairs · %d id-less tool-call rows since boot", f.dupePairs, f.idless)
	}
	return doctorPass, "no duplicate or id-less tool-call rows"
}

func checkPricing(f doctorFacts) (string, string) {
	claude := f.claudePriced + f.claudeUnpriced
	if claude == 0 {
		return doctorSkip, "no Claude model calls"
	}
	detail := fmt.Sprintf("%d of %d Claude calls priced (%d%%) · all models: %d of %d calls unpriced",
		f.claudePriced, claude, pct(f.claudePriced, claude), f.allUnpriced, f.allCalls)
	if f.claudePriced*100 < claude*90 {
		return doctorFail, detail
	}
	return doctorPass, detail
}

func checkRetention(f doctorFacts) (string, string) {
	var evicting []string
	for _, k := range f.retention {
		if k.Rows < k.Budget {
			continue
		}
		oldest, err := time.Parse(time.RFC3339, k.OldestTS)
		if err != nil {
			continue
		}
		if age := f.now.Sub(oldest); age < doctorEvictWindow {
			evicting = append(evicting, fmt.Sprintf("%s %d/%d rows, oldest %s", k.Name, k.Rows, k.Budget, age.Round(time.Minute)))
		}
	}
	if len(evicting) > 0 {
		return doctorFail, "at budget with under 24h kept: " + strings.Join(evicting, "; ")
	}
	return doctorPass, fmt.Sprintf("%d kinds within budget", len(f.retention))
}

func checkEgressRouting(f doctorFacts) (string, string) {
	switch {
	case !f.st.ProxyEnabled:
		return doctorPass, "proxy off — egress not inspected"
	case f.st.UninspectedEgress > 0:
		return doctorFail, fmt.Sprintf("%d endpoints reached outside the proxy", f.st.UninspectedEgress)
	}
	return doctorPass, "all agent egress routed through the proxy"
}

func checkBus(f doctorFacts) (string, string) {
	if f.st.BusDrops > 0 {
		return doctorFail, fmt.Sprintf("%d events dropped by full subscriber buffers", f.st.BusDrops)
	}
	return doctorPass, "no dropped events"
}
