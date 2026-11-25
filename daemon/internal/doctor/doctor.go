// Package doctor derives the daemon's self-check report from gathered facts:
// every check is a pure function of Facts.
package doctor

import (
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Check is one self-check verdict. State is pass, fail or skip; Fix is a
// one-line remedy, set only on fail.
type Check struct {
	ID     string
	Title  string
	State  string
	Detail string
	Fix    string
}

// Summary counts checks by state.
type Summary struct {
	Pass int
	Fail int
	Skip int
}

// LossReview records review of history without clearing live faults.
type LossReview struct {
	SeenAt  string
	Pending bool
}

// Report is the verdict on coverage. Grace is true inside the boot window,
// where steady-state checks skip.
type Report struct {
	GeneratedAt string
	LossReview  LossReview
	Version     string
	Uptime      string
	Grace       bool
	Summary     Summary
	Checks      []Check // fixed order; never nil
}

const (
	Pass = "pass"
	Fail = "fail"
	Skip = "skip"

	GraceDetail = "inside the 10-minute boot window"
	// spoolStale: a running root ES service whose spool is older than this
	// while agents are active is not writing.
	spoolStale = 10 * time.Minute
	// evictWindow: a row cap whose oldest kept row is younger than this is
	// evicting inside one day.
	evictWindow = 24 * time.Hour
)

// Facts is everything the checks read, gathered once per report so each
// check is a pure function of it.
type Facts struct {
	Now, Boot time.Time
	Grace     bool
	Status    posture.Status

	// ClaudeActive is whether a Claude Code process is running.
	ClaudeActive         bool
	SettingsKnown        bool
	HookRegistered       bool
	HookDuplicate        bool
	HookHarnesses        []string
	MissingHookHarnesses []string

	sessionsTotal, sessionsNamed               int
	sessionsWithWorkspace, sessionsWRepo       int
	sessionsWithGitWorkspace, sessionsGitWRepo int
	repoQueryError                             bool
	sessionsLastHour                           int
	sessionsByHarness, traceByHarness          map[string]int
	// SeenByHarness counts sessions with a transcript line read or a hook
	// event since boot.
	SeenByHarness map[string]int

	dupePairs, idless int

	claudePriced, claudeUnpriced, allUnpriced, allCalls int

	retention []store.KindRetention

	// Egress is the blind-spot rows behind Status.UninspectedEgress (same window).
	Egress []EgressRow

	Hermes *collect.HermesStatus // nil when the collector is not wired

	ConfigBoot, ConfigReload string
	ConfigRestart            []string

	// LossSeen is the operator's mark that earlier losses were seen.
	LossSeen *collect.LossSeen
}

// EgressRow is one uninspected endpoint as the egress check reads it.
type EgressRow struct {
	Agent, Host, Infra, AgentKind string
}

type probe struct {
	id, title, fix string
	run            func(f Facts) (state, detail string)
}

// probes run in this order; the report lists them in it.
var probes = []probe{
	{"config", "Configuration", "Fix ~/.config/secure-agent/config.yaml, then restart Secure Agent: firewall, guard and paths load only at start", checkConfig},
	{"hook-registered", "Guard hook registered", "Run Setup → Harness hooks", checkHookRegistered},
	{"hook-active", "Guard hook active", "Open Setup → Harness Hooks to check registration, then start a new harness session and run a guarded tool such as Bash. Installing hooks alone does not prove activity in existing sessions.", checkHookActive},
	{"file-telemetry", "File telemetry", "System Settings → Privacy & Security → Full Disk Access → Secure Agent, or the Setup card — a flooding writer: Reinstall the file telemetry helper from the Setup card", CheckFileTelemetry},
	{"collectors", "Collectors", "Restart Secure Agent from the menu bar; file monitoring that keeps stopping needs Full Disk Access (Setup)", checkCollectors},
	{"trace-coverage", "Trace coverage", "Restart Secure Agent; a harness that stays untraced has no transcript reader running", checkTraceCoverage},
	{"hermes", "Hermes Agent trace", "Point hermes_home at the Hermes root; a state.db this version cannot read needs a Secure Agent update", CheckHermes},
	{"session-identity", "Session identity", "Check the Sessions tab for unnamed sessions; their processes were not recognized as a harness", checkSessionIdentity},
	{"session-repo", "Session repo attribution", "Restart Secure Agent to re-resolve repo and branch; a workspace outside a git checkout has no repo", checkSessionRepo},
	{"session-rate", "Session creation rate", "Check the Sessions tab for the harness creating stub sessions", checkSessionRate},
	{"tool-pairing", "Tool-call pairing", "Update Secure Agent so every harness adapter sends a call id; rows already stored stay unpaired", checkToolPairing},
	{"pricing", "Model-call pricing", "Update Secure Agent so its price table covers the Claude models in use", checkPricing},
	{"retention", "Event retention", "Find the process flooding these kinds in the Events tab; their rows are evicted inside a day", checkRetention},
	{"egress-routing", "Egress routing", "turn on Settings → Secure Agent → Traffic → Route Claude Code through Secure Agent, source agent-env.sh where other agents launch, or Allow the endpoints in Protection → Traffic", checkEgressRouting},
	{"bus", "Event bus", "Monitoring history for this run is incomplete. If the count keeps increasing, update Secure Agent and check for a collector flooding Events. Restarting cannot recover lost deliveries.", CheckBus},
	{"storage", "Evidence storage", "Check free disk space and state-directory permissions; earlier failed writes cannot be recovered by restarting", CheckStorage},
}

// ProbeIDs lists the check ids in report order.
func ProbeIDs() []string {
	ids := make([]string, len(probes))
	for i, p := range probes {
		ids[i] = p.id
	}
	return ids
}

// Build runs every check against f and assembles the report.
func Build(f Facts) Report {
	rep := Report{
		GeneratedAt: f.Now.UTC().Format(time.RFC3339Nano),
		Version:     f.Status.Version,
		Uptime:      f.Status.Uptime,
		Grace:       f.Grace,
		Checks:      make([]Check, 0, len(probes)),
	}
	seen := f.LossSeen.SeenAt()
	if !seen.IsZero() {
		rep.LossReview.SeenAt = seen.Format(time.RFC3339Nano)
	}
	unreviewed := func(count uint64, at *time.Time) bool {
		return count > 0 && (at == nil || seen.Before(*at))
	}
	rep.LossReview.Pending = unreviewed(f.Status.BusDrops, f.Status.BusDropAt)
	if es := f.Status.ESService; es != nil {
		rep.LossReview.Pending = rep.LossReview.Pending || unreviewed(es.BytesLost, es.LostAt)
	}
	for _, p := range probes {
		state, detail := p.run(f)
		c := Check{ID: p.id, Title: p.title, State: state, Detail: detail}
		switch state {
		case Pass:
			rep.Summary.Pass++
		case Fail:
			rep.Summary.Fail++
			c.Fix = p.fix
			if p.id == "file-telemetry" && f.Status.ESService != nil && f.Status.ESService.Losing {
				c.Fix = "Reduce sustained event load and check delivery lag. The gap remains for this run; reinstalling the helper or restarting cannot recover overwritten evidence."
			}
		default:
			rep.Summary.Skip++
		}
		rep.Checks = append(rep.Checks, c)
	}
	return rep
}
