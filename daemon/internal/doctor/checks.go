package doctor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

func pct(n, total int) int { return 100 * n / total }

// checkConfig fails while a boot or reload problem stands, or while the file
// holds start-only settings the running daemon does not. A reload that read
// the same unchanged problem as boot is reported once, as the boot one.
func checkConfig(f Facts) (string, string) {
	const bootTail = "; settings it could not set started on built-in defaults, and firewall, guard and paths keep them until restart"
	var parts []string
	switch {
	case f.ConfigBoot != "" && f.ConfigReload != "" && f.ConfigReload != f.ConfigBoot:
		parts = append(parts, "at start: "+f.ConfigBoot+bootTail, "latest reload skipped: "+f.ConfigReload)
	case f.ConfigBoot != "":
		parts = append(parts, "at start: "+f.ConfigBoot+bootTail)
	case f.ConfigReload != "":
		parts = append(parts, "latest reload skipped, the running settings are kept: "+f.ConfigReload)
	}
	if len(f.ConfigRestart) > 0 {
		parts = append(parts, "changed since start, applied after restart: "+strings.Join(f.ConfigRestart, ", "))
	}
	if len(parts) == 0 {
		return Pass, "config.yaml loaded"
	}
	return Fail, strings.Join(parts, "; ")
}

func checkHookRegistered(f Facts) (string, string) {
	switch {
	case !f.ClaudeActive:
		return Skip, "Claude Code is not running; registration check does not apply to other harnesses"
	case !f.SettingsKnown:
		return Skip, "home directory unknown"
	case f.HookDuplicate:
		return Fail, "marketplace and manual Claude hooks both configured; remove one route"
	case !f.HookRegistered:
		return Skip, "optional guard hooks are not configured"
	}
	return Pass, "registered for PreToolUse and PostToolUse"
}

func checkHookActive(f Facts) (string, string) {
	if len(f.HookHarnesses) == 0 {
		return Skip, "no active harness with a supported guard hook"
	}
	if len(f.MissingHookHarnesses) > 0 {
		return Skip, "no attributed hook activity in 24h: " + strings.Join(f.MissingHookHarnesses, ", ")
	}
	return Pass, "recent attributed hook activity: " + strings.Join(f.HookHarnesses, ", ")
}

// CheckFileTelemetry judges the file telemetry spool service.
func CheckFileTelemetry(f Facts) (string, string) {
	if posture.FileTelemetryDisabled(f.Status) {
		return Skip, "file telemetry is disabled in configuration"
	}
	if posture.FileTelemetryUnavailable(f.Status) {
		return Fail, "file telemetry is enabled but no file collector is available"
	}
	if f.Status.FileTelemetryEnabled == nil && f.Status.ESService == nil {
		configured := false
		for _, c := range f.Status.Collectors {
			configured = configured || c.Name == "eslogger"
		}
		if !configured {
			return Skip, "optional file telemetry is not configured"
		}
	}
	es := f.Status.ESService
	if es == nil {
		return Skip, "not spool-based"
	}
	if es.Losing {
		return Fail, posture.ESLossDetail(*es)
	}
	if title, detail := posture.CollectorFailure(f.Now, *es); title != "" {
		return Fail, detail
	}
	switch {
	case posture.ESServiceFlooding(f.Now, *es):
		return Fail, posture.ESFloodingDetail(*es)
	case posture.ESServiceLagging(f.Now, *es):
		return Fail, posture.ESLaggingDetail(*es)
	case posture.ESServiceBehind(f.Now, *es):
		// No warning level exists (Pass/Fail/Skip only): a sustained burst
		// still fails the check, but with the behind detail, not the garbage
		// one.
		return Fail, posture.ESBehindDetail(*es)
	case es.State == "not-loaded":
		return Fail, "root service not loaded"
	case posture.ESServiceRefused(es.State):
		return Fail, "root service state: " + es.State + " — " + posture.ESReregisterHint
	case posture.ESServiceRunning(es.State) && es.Collector != nil && es.Collector.Fresh(f.Now) && es.Collector.State == "collecting":
		return Pass, "file collector is ready"
	case posture.ESServiceFailing(es.State):
		return Fail, "root service state: " + es.State
	case posture.ESServiceRunning(es.State) && f.Status.ActiveAgents > 0 && !f.Grace && f.Now.Sub(es.SpoolMtime) > spoolStale:
		if es.SpoolMtime.IsZero() {
			return Fail, "service running but spool absent"
		}
		return Fail, fmt.Sprintf("service running but spool not written for %d min", int(f.Now.Sub(es.SpoolMtime).Minutes()))
	}
	if es.BytesLost > 0 && es.LostAt != nil {
		return Pass, fmt.Sprintf("%s · %d unread spool bytes lost at %s, none since", es.State, es.BytesLost, es.LostAt.Local().Format("15:04"))
	}
	return Pass, es.State
}

func checkCollectors(f Facts) (string, string) {
	if f.Grace {
		return Skip, GraceDetail
	}
	var down, silent []string
	var enabledCount int
	for _, c := range f.Status.Collectors {
		if c.Name == "eslogger" && posture.FileTelemetryDisabled(f.Status) {
			continue
		}
		enabledCount++
		switch {
		case c.Abandoned:
			down = append(down, c.Name+" (abandoned)")
		case !c.Running:
			down = append(down, c.Name+" (stopped)")
		}
	}
	// Readiness failures are actionable; an idle source alone is not.
	// The spool service's own failures are the file-telemetry check's.
	spoolFailing := f.Status.ESService != nil && len(posture.ESServiceItems(f.Now, *f.Status.ESService)) > 0
	if f.Status.ActiveAgents > 0 {
		for _, it := range posture.SilentCollectorItems(f.Now, f.Status) {
			if !posture.IsMonitoringGap(it) {
				continue
			}
			if it.ID == "eslogger" && spoolFailing {
				continue
			}
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
	for _, c := range f.Status.Collectors {
		if c.Name == "eslogger" && posture.FileTelemetryDisabled(f.Status) {
			continue
		}
		if c.Source != "" {
			polls += fmt.Sprintf(" · %s %s @ %d polled %s", c.Name, c.Source, c.Watermark, c.LastPoll)
		}
	}
	if len(parts) > 0 {
		return Fail, strings.Join(parts, " · ") + polls
	}
	return Pass, fmt.Sprintf("%d collectors running", enabledCount) + polls
}

// CheckHermes reports the Hermes Agent collector: state not found when no
// state.db exists under its root, else each database's watermark and the
// last poll, failing when a database could not be read.
func CheckHermes(f Facts) (string, string) {
	h := f.Hermes
	switch {
	case h == nil:
		return Skip, "not wired"
	case h.LastError != "":
		return Fail, h.LastError
	case len(h.DBs) == 0:
		return Skip, fmt.Sprintf("state.db not found under %s; set hermes_home or export HERMES_STATE_DIR/HERMES_HOME in the daemon's environment or login shell", h.Root)
	}
	dbs := make([]string, len(h.DBs))
	for i, d := range h.DBs {
		dbs[i] = fmt.Sprintf("%s @ message %d", d.Path, d.Watermark)
	}
	return Pass, strings.Join(dbs, ", ") + " · polled " + h.LastPoll.UTC().Format(time.RFC3339)
}

// checkTraceCoverage fails for a harness whose sessions had a transcript line
// read or a hook event since boot (a conversation that started before boot
// counts) while none of its trace rows were written since boot. A session
// whose process only stayed alive is idle, not seen.
func checkTraceCoverage(f Facts) (string, string) {
	if f.Grace {
		return Skip, GraceDetail
	}
	if len(f.SeenByHarness) == 0 {
		return Skip, "no sessions since boot"
	}
	var blind, traced []string
	for h, n := range f.SeenByHarness {
		if f.traceByHarness[h] == 0 {
			blind = append(blind, h)
		} else {
			traced = append(traced, fmt.Sprintf("%s (%d sessions)", h, n))
		}
	}
	if len(blind) > 0 {
		sort.Strings(blind)
		return Fail, "sessions since boot but no trace rows: " + strings.Join(blind, ", ")
	}
	sort.Strings(traced)
	return Pass, fmt.Sprintf("%d harnesses traced: %s", len(traced), strings.Join(traced, ", "))
}

func checkSessionIdentity(f Facts) (string, string) {
	if f.Grace {
		return Skip, GraceDetail
	}
	if f.sessionsTotal == 0 {
		return Skip, "no sessions since boot"
	}
	detail := fmt.Sprintf("%d of %d sessions since boot carry a harness (%d%%)", f.sessionsNamed, f.sessionsTotal, pct(f.sessionsNamed, f.sessionsTotal))
	if f.sessionsNamed*100 < f.sessionsTotal*80 {
		return Fail, detail + ", want ≥ 80%"
	}
	return Pass, detail
}

func checkSessionRepo(f Facts) (string, string) {
	if f.Grace {
		return Skip, GraceDetail
	}
	if f.repoQueryError {
		return Fail, "could not inspect workspace attribution"
	}
	if f.sessionsWithWorkspace == 0 {
		named := 0
		for _, n := range f.sessionsByHarness {
			named += n
		}
		if named == 0 {
			return Skip, "no named sessions since boot"
		}
		return Fail, fmt.Sprintf("0 of %d named sessions since boot carry a workspace — attribution drop", named)
	}
	if f.sessionsWithGitWorkspace == 0 {
		return Skip, fmt.Sprintf("%d workspace sessions since boot, none inside Git checkouts", f.sessionsWithWorkspace)
	}
	detail := fmt.Sprintf("%d of %d sessions in Git workspaces since boot carry a repo (%d%%)",
		f.sessionsGitWRepo, f.sessionsWithGitWorkspace, pct(f.sessionsGitWRepo, f.sessionsWithGitWorkspace))
	if f.sessionsGitWRepo*100 < f.sessionsWithGitWorkspace*50 {
		return Fail, detail + ", want ≥ 50%"
	}
	return Pass, detail
}

func checkSessionRate(f Facts) (string, string) {
	if f.Grace {
		return Skip, GraceDetail
	}
	if f.Status.ActiveAgents == 0 {
		return Skip, "no agents running"
	}
	budget := 2*f.Status.ActiveAgents + 10
	if f.sessionsLastHour > budget {
		return Fail, fmt.Sprintf("%d sessions created in the last hour, budget %d for %d agents", f.sessionsLastHour, budget, f.Status.ActiveAgents)
	}
	return Pass, fmt.Sprintf("%d sessions created in the last hour (budget %d)", f.sessionsLastHour, budget)
}

func checkToolPairing(f Facts) (string, string) {
	if f.dupePairs > 0 || f.idless > 0 {
		return Fail, fmt.Sprintf("%d duplicate (session, call_id) pairs · %d id-less tool-call rows since boot", f.dupePairs, f.idless)
	}
	return Pass, "no duplicate or id-less tool-call rows"
}

func checkPricing(f Facts) (string, string) {
	claude := f.claudePriced + f.claudeUnpriced
	if claude == 0 {
		return Skip, "no Claude model calls"
	}
	detail := fmt.Sprintf("%d of %d Claude calls priced (%d%%) · all models: %d of %d calls unpriced",
		f.claudePriced, claude, pct(f.claudePriced, claude), f.allUnpriced, f.allCalls)
	if f.claudePriced*100 < claude*90 {
		return Fail, detail
	}
	return Pass, detail
}

// checkRetention fails when a row cap evicts rows younger than a day: any
// kind's record rows, or a kind outside the ring kinds. A ring kind's newest
// rows covering minutes is its design, reported as detail.
func checkRetention(f Facts) (string, string) {
	var evicting, ring []string
	for _, k := range f.retention {
		if age, ok := horizonAge(f.Now, k.RecordHorizonTS); ok && age < evictWindow {
			evicting = append(evicting, fmt.Sprintf("%s record %d/%d rows, oldest %s", k.Name, k.RecordRows, k.RecordBudget, age.Round(time.Minute)))
		}
		age, ok := horizonAge(f.Now, k.HorizonTS)
		switch {
		case !ok || age >= evictWindow:
		case k.Ring:
			ring = append(ring, fmt.Sprintf("%s %s", k.Name, age.Round(time.Minute)))
		default:
			evicting = append(evicting, fmt.Sprintf("%s %d/%d rows, oldest %s", k.Name, k.Rows, k.Budget, age.Round(time.Minute)))
		}
	}
	if len(evicting) > 0 {
		return Fail, "at budget with under 24h kept: " + strings.Join(evicting, "; ")
	}
	detail := fmt.Sprintf("%d kinds within budget", len(f.retention))
	if len(ring) > 0 {
		detail += "; newest rows only (record rows keep days): " + strings.Join(ring, ", ")
	}
	return Pass, detail
}

// horizonAge is how long ago an RFC3339 horizon was; false when there is none.
func horizonAge(now time.Time, ts string) (time.Duration, bool) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return now.Sub(t), true
}

func checkEgressRouting(f Facts) (string, string) {
	switch {
	case !f.Status.ProxyEnabled:
		return Pass, "proxy off — egress not inspected"
	case f.Status.UninspectedEgress > 0:
		detail := fmt.Sprintf("%d endpoints reached outside the proxy", f.Status.UninspectedEgress)
		if by := egressByAgent(f.Egress); by != "" {
			detail += ": " + by
		}
		return Fail, detail
	case f.Status.ProxyTunneled+f.Status.ProxyDecrypted > 0:
		return Pass, fmt.Sprintf("all agent egress routed through the proxy · %d connections since start (%d decrypted)",
			f.Status.ProxyTunneled+f.Status.ProxyDecrypted, f.Status.ProxyDecrypted)
	}
	return Pass, "all agent egress routed through the proxy"
}

// egressByAgent names the agents behind the headline count — the rows that
// join it (no infra family, no known CDN or cloud host) — most endpoints
// first, with up to two hosts each: "codex 4 (api.openai.com, chatgpt.com),
// cursor 1 (api2.cursor.sh)". "" when no row joins the headline.
func egressByAgent(rows []EgressRow) string {
	type agentRows struct {
		name  string
		hosts []string
	}
	var order []*agentRows
	byName := map[string]*agentRows{}
	for _, r := range rows {
		if r.AgentKind == config.AgentKindInfra || r.Infra != "" || r.Agent == "" {
			continue
		}
		a := byName[r.Agent]
		if a == nil {
			a = &agentRows{name: r.Agent}
			byName[r.Agent] = a
			order = append(order, a)
		}
		a.hosts = append(a.hosts, r.Host)
	}
	sort.SliceStable(order, func(i, j int) bool { return len(order[i].hosts) > len(order[j].hosts) })
	parts := make([]string, 0, len(order))
	for _, a := range order {
		hosts := a.hosts
		more := ""
		if len(hosts) > 2 {
			hosts, more = hosts[:2], ", …"
		}
		parts = append(parts, fmt.Sprintf("%s %d (%s%s)", a.name, len(a.hosts), strings.Join(hosts, ", "), more))
	}
	return strings.Join(parts, ", ")
}

// CheckBus judges subscriber delivery drops.
func CheckBus(f Facts) (string, string) {
	if f.Status.BusDropping {
		return Fail, fmt.Sprintf("%d subscriber deliveries dropped since daemon start", f.Status.BusDrops)
	}
	if f.Status.BusDrops > 0 && f.Status.BusDropAt != nil {
		return Pass, fmt.Sprintf("%d subscriber deliveries dropped, the last at %s, none since", f.Status.BusDrops, f.Status.BusDropAt.Local().Format("15:04"))
	}
	return Pass, "no dropped events"
}

// CheckStorage judges evidence read and write health.
func CheckStorage(f Facts) (string, string) {
	h := f.Status.StorageHealth
	if h == nil {
		return Skip, "storage health unavailable"
	}
	if len(h.ReadActive) > 0 {
		return Fail, "evidence reads unavailable: " + strings.Join(h.ReadActive, ", ") + posture.ReadIssueDetail(*h)
	}
	if h.Failures == 0 {
		return Pass, "no failed evidence writes"
	}
	if len(h.Active) > 0 {
		return Fail, fmt.Sprintf("%d failed persistence attempts since start; still failing: %s", h.Failures, strings.Join(h.Active, ", "))
	}
	return Pass, fmt.Sprintf("new writes recovered; %d earlier failures may have left evidence gaps", h.Failures)
}
