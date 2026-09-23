package daemon

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agentenv"
	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/otlp"
	"github.com/cavi-ai/secure-agent/daemon/internal/proxy"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// wire.go — the daemon's component wiring, extracted from main() into
// individually testable units. Each function builds one component (or one
// closure) from explicit inputs; main() is left as pure orchestration.

// firewallStack bundles the egress-inspection components and the two
// closures the API layer needs for live policy changes.
type firewallStack struct {
	Engine      *firewall.Engine
	Modes       *firewall.ModeStore
	Sources     *firewall.SourceStore
	BaseSources []string
	Reload      func() error
	Ingest      func() ([]string, error)
}

// setupFirewall builds the engine and its persisted overrides (salt, rule
// modes, registered fingerprints, user ingest sources). Degradations are
// loud, never silent: a missing salt disables fingerprinting with an ERROR
// log; a failed engine logs and leaves Engine nil (the daemon still runs).
func setupFirewall(cfg config.Config) *firewallStack {
	stateDir := filepath.Dir(cfg.Firewall.Registry.SaltRef)

	fwSalt, saltErr := firewall.LoadSalt(cfg.Firewall.Registry.SaltRef)
	if saltErr != nil {
		// Loud degradation: the fingerprint layer is OFF, not silently broken.
		// (A silently rotated salt orphans every registered fingerprint while
		// the status page still says the firewall is up.)
		log.Printf("ERROR: firewall salt unavailable, known-secret fingerprinting disabled: %v", saltErr)
	}
	fwEngine, fwErr := firewall.NewEngine(cfg.Firewall, fwSalt)
	if fwErr != nil {
		log.Printf("Failed to initialize firewall engine: %v", fwErr)
	}
	// Apply any persisted rule-mode overrides (e.g. rules promoted to block in a
	// previous session) on top of the config defaults.
	fwModes := firewall.NewModeStore(filepath.Join(stateDir, "firewall-modes.json"))
	if fwEngine != nil {
		for rule, mode := range fwModes.Load() {
			fwEngine.SetRuleMode(rule, firewall.ParseMode(mode))
		}
	}

	// Known-secret fingerprints: config defaults plus any registered by
	// `secure-agent fingerprint`. Reapplied on demand via /firewall/fingerprints/reload.
	fpStore := firewall.NewFingerprintStore(filepath.Join(stateDir, "firewall-fingerprints.json"))

	// User-added ingest sources (registered from the console) persist alongside
	// the mode and fingerprint overrides, so a source survives a restart without
	// editing the config overlay.
	srcStore := firewall.NewSourceStore(filepath.Join(stateDir, "firewall-sources.json"))
	reload := func() error {
		combined := append(append([]config.Fingerprint{}, cfg.Firewall.Registry.Fingerprints...), fpStore.Load()...)
		if fwEngine != nil {
			fwEngine.SetFingerprints(combined)
		}
		return nil
	}
	_ = reload() // apply persisted fingerprints on startup

	// ingest scans the configured secret sources, registers their HMAC
	// fingerprints, and applies them live. Triggered by `secure-agent fingerprint`.
	ingest := func() ([]string, error) {
		// Effective sources are computed at call time: the config defaults plus
		// any user-added sources (expanded here — they are stored raw).
		sources := append([]string{}, cfg.Firewall.Registry.IngestSources...)
		for _, s := range srcStore.Load() {
			sources = append(sources, config.ExpandPath(s))
		}
		fps, err := firewall.Ingest(sources, fwSalt)
		if err != nil {
			return nil, err
		}
		if err := fpStore.Save(fps); err != nil {
			return nil, err
		}
		_ = reload()
		labels := make([]string, 0, len(fps))
		for _, fp := range fps {
			labels = append(labels, fp.Label)
		}
		return labels, nil
	}

	return &firewallStack{
		Engine:      fwEngine,
		Modes:       fwModes,
		Sources:     srcStore,
		BaseSources: cfg.Firewall.Registry.IngestSources,
		Reload:      reload,
		Ingest:      ingest,
	}
}

// setupProxy builds the opt-in MITM proxy with its CA, dashboard handler, and
// the per-install proxy token written into the agent routing snippet. Returns
// nil (with a log) when the CA cannot be initialized.
func setupProxy(cfg config.Config, b *bus.Bus, eng *firewall.Engine) *proxy.ProxyServer {
	caMgr, err := proxy.NewCAManager(cfg.ProxyCACertPath, cfg.ProxyCAKeyPath)
	if err != nil {
		log.Printf("Failed to initialize Proxy CA Manager: %v", err)
		return nil
	}
	proxyServer := proxy.NewProxyServer(cfg.ProxyPort, b, caMgr, eng)
	// The documented console URL lives on the proxy's loopback HTTP
	// port; serve the same embedded assets the unix API serves.
	if h := api.DashboardHandler(); h != nil {
		proxy.SetDashboardHandler(http.StripPrefix("/dashboard/", h))
	}
	// Per-install proxy token: the loopback listener must not be a free
	// open proxy for other local processes. The token is generated next
	// to the salt (0600) and embedded in the snippet the user sources.
	proxyToken := proxy.LoadToken(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "proxy-token"))
	// Write the opt-in routing snippet into our own config dir. It does
	// nothing until the user sources it; we never edit their shell rc.
	if snippetPath, werr := agentenv.WriteSnippet(filepath.Dir(cfg.ProxyCACertPath), cfg.ProxyPort, cfg.ProxyCACertPath, proxyToken); werr == nil {
		log.Printf("agent routing snippet: %s (source it to route agents through the proxy)", snippetPath)
	}
	return proxyServer
}

// guardBrokerMS derives the broker's resolve deadline from the hook's own
// deadline: 3s shorter, so the hook always receives an explicit deny from the
// daemon rather than a dropped socket (the server must resolve first).
// Floored at 1s so a misconfigured hook deadline can't produce a zero/negative
// broker deadline.
func guardBrokerMS(hookDeadlineMS int) int {
	if hookDeadlineMS <= 0 {
		hookDeadlineMS = 45000
	}
	brokerMS := hookDeadlineMS - 3000
	if brokerMS < 1000 {
		brokerMS = 1000
	}
	return brokerMS
}

// transcriptTailTargets are the log paths the transcript scanner tails: each
// harness's activity logs, its session transcripts by shape
// (collect.HarnessTranscriptGlobs — globs, never a directory walk), the hook
// activity log, and the daemon's own JSONL sink when configured. Harness logs
// in other formats (gemini's logs.json) get format support with the P2 trace
// work.
func transcriptTailTargets(home, jsonlPath string) []string {
	// CODEX_HOME moves Codex's rollout store out of ~/.codex; sessions then
	// run while zero transcripts are written under ~/.codex/sessions.
	// Default to both so a default install is still covered.
	codexHome := os.Getenv("CODEX_HOME")
	targets := []string{
		filepath.Join(home, ".claude", "logs", "*.jsonl"),
		// Legacy Cursor logs (empty on current builds, whose transcripts are
		// the agent-transcripts shape).
		filepath.Join(home, ".cursor", "logs", "*.jsonl"),
	}
	targets = append(targets, collect.HarnessTranscriptGlobs(home)...)
	targets = append(targets, filepath.Join(home, ".local", "state", "secure-agent", "activity.jsonl"))
	if codexHome != "" && codexHome != filepath.Join(home, ".codex") {
		targets = append(targets, collect.CodexRolloutGlob(codexHome))
	}
	if jsonlPath != "" {
		targets = append(targets, jsonlPath)
	}
	return targets
}

// codexSessionTargets discovers CODEX_HOME off LIVE codex processes: an
// orchestrator that runs codex with a relocated home writes rollouts outside
// ~/.codex, and the daemon's own env never sees it. Reading the variable off
// the process itself (same mechanism as `ps eww`) keeps the tail targets
// correct without a daemon restart. Called on the transcript scanner's
// resolve cadence.
func codexSessionTargets(tagger *agents.Tagger, home string) []string {
	if tagger == nil {
		return nil
	}
	return codexSessionTargetsFrom(tagger.TaggedPIDs(), agents.ProcEnvVar, home)
}

// codexSessionTargetsFrom is the testable core: deduped rollout globs under
// each tagged codex process's CODEX_HOME, minus the default already covered.
func codexSessionTargetsFrom(procs map[int32]agents.AgentInfo, envOf func(int32, string) string, home string) []string {
	def := collect.CodexRolloutGlob(filepath.Join(home, ".codex"))
	seen := map[string]bool{}
	var out []string
	for pid, info := range procs {
		if info.Name != "codex" {
			continue
		}
		ch := envOf(pid, "CODEX_HOME")
		if ch == "" {
			continue
		}
		glob := collect.CodexRolloutGlob(ch)
		if glob == def || seen[glob] {
			continue
		}
		seen[glob] = true
		out = append(out, glob)
	}
	return out
}

// isTraceKind reports whether an event is an agent-semantic trace record the
// fleet wire carries (tool calls, turns, model calls) — not the raw OS flood.
func isTraceKind(k event.Kind) bool {
	switch k {
	case event.KindToolCall, event.KindTurn, event.KindModelCall:
		return true
	}
	return false
}

// isUnattributedFileEvent: a file open, write or delete that resolved to no
// session — its process is outside every agent family.
func isUnattributedFileEvent(e event.Event) bool {
	if e.SessionID != "" {
		return false
	}
	switch e.Kind {
	case event.KindFileOpen, event.KindFileWrite, event.KindFileDelete:
		return true
	}
	return false
}

// startDrainLoop consumes the bus, persisting events and correlating flags →
// incidents → fleet webhooks. The returned channel closes once every delivered
// event has been persisted, so shutdown can wait for it instead of dropping
// the final, most-relevant events/flags/incident around a kill or quit.
// adv may be nil (advisor disabled); when set, new flags/incidents are also
// offered for advisory triage — enqueueing is non-blocking and drop-safe.
// advGet resolves the CURRENT advisor per event: config hot-reload swaps
// the stack while the drain loop is mid-event, and a nil getter result
// (advisor disabled) must drop routing without touching the loop itself.
func startDrainLoop(sub <-chan event.Event, st *store.Store, cr *correlate.Correlator, pub *fleet.Publisher, res *session.Resolver, deltas *api.DeltaHub, otlpExp *otlp.Exporter, postureChanged func(), advGet func() *advisor.Subscriber) <-chan struct{} {
	analyzer := intel.NewAnalyzer()
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for e := range sub {
			// Attribute before anything else: the stored event, the flags it
			// triggers, and the incident all carry the session id.
			res.Resolve(&e)
			flags := cr.Observe(e)
			// File activity outside every agent family is kept only as the
			// evidence of a flag it raised: system-wide opens (indexers,
			// builds, the daemon itself) outnumber agent file activity by
			// orders of magnitude and would push it out of the per-kind
			// row budget.
			if len(flags) == 0 && isUnattributedFileEvent(e) {
				continue
			}
			st.PutEvent(e)
			if deltas != nil {
				// Guard lifecycle keeps its own delta names (the menubar's
				// instant prompt path keys on them); everything else is a
				// generic typed event for timeline/console patching.
				kind := "event"
				if e.Kind == event.KindGuardPrompt || e.Kind == event.KindGuardResolved {
					kind = e.Kind.String()
				}
				deltas.Publish(api.Delta{Type: kind, Data: e})
			}
			// Traces cross the fleet wire too (opt-in per sink): a collector
			// showing cross-node sessions needs the tool/model calls, not just
			// the security events. Lossy by design — the publisher's in-flight
			// cap drops trace overflow before it can starve flags.
			if isTraceKind(e.Kind) {
				if pub != nil {
					pub.Publish(fleet.EventTrace, e)
				}
				otlpExp.TraceEvent(e)
			}
			for _, fl := range flags {
				if fl.SessionID == "" {
					fl.SessionID = e.SessionID
				}
				// Stamp the workspace so per-workspace notification scopes can
				// key on it without re-resolving the session later.
				if fl.Workspace == "" && fl.SessionID != "" {
					fl.Workspace = res.WorkspaceFor(fl.SessionID)
				}
				log.Printf("FLAG TRIGGERED [%d]: %s (pid %d agent %s)", fl.Severity, fl.Rule, fl.PID, fl.Agent)
				st.PutFlag(fl)
				if deltas != nil {
					deltas.Publish(api.Delta{Type: "flag", Data: fl})
				}
				if pub != nil {
					pub.Publish(fleet.EventFlag, fl)
				}
				if advGet != nil {
					if adv := advGet(); adv != nil {
						adv.EnqueueFlag(fl)
					}
				}

				// Incidents aggregate: one per rule+session+subject, flags
				// become its evidence. The 323-identical-flags storm becomes
				// one incident with a count, not 323 reports.
				subject := intel.SubjectForFlag(fl)
				if openID, found := st.FindOpenIncident(fl.Rule, fl.SessionID, subject); found {
					if updated, ok := st.AggregateIntoIncident(openID, fl.ID, fl.TS); ok && deltas != nil {
						deltas.Publish(api.Delta{Type: "incident", Data: updated})
					}
					if postureChanged != nil {
						postureChanged()
					}
					continue
				}

				recentEvs := st.RecentEvents(100)
				report := analyzer.Analyze(fl, recentEvs)
				report.SessionID = fl.SessionID
				report.Subject = subject
				report.AggregateCount = 1
				st.PutIncident(report)
				if deltas != nil {
					deltas.Publish(api.Delta{Type: "incident", Data: report})
				}
				log.Printf("INCIDENT CREATED [%s]: %s (Risk: %s, %d rotate items)", report.ID, report.Summary, report.Risk, len(report.RotateList))
				if pub != nil {
					pub.Publish(fleet.EventIncident, report)
				}
				if advGet != nil {
					if adv := advGet(); adv != nil {
						adv.EnqueueIncident(report)
					}
				}
			}
			if len(flags) > 0 && postureChanged != nil {
				postureChanged()
			}
			if (e.Kind == event.KindGuardPrompt || e.Kind == event.KindGuardResolved) && postureChanged != nil {
				postureChanged()
			}
		}
	}()
	return drainDone
}

// advisorStack bundles the advisor subscriber and, in managed mode, the model
// server process the daemon supervises.
type advisorStack struct {
	Sub     *advisor.Subscriber
	Managed *exec.Cmd // nil unless advisor.managed
}

// setupAdvisor builds the local triage advisor: nil unless explicitly
// enabled in config (and silently nil never happens — a misconfigured
// endpoint logs why). In managed mode the model server is spawned here and
// supervised alongside the subscriber in main.
func setupAdvisor(cfg config.Config, st *store.Store) advisorStack {
	endpoint := cfg.Advisor.Endpoint
	model := cfg.Advisor.Model
	var managed *exec.Cmd
	if cfg.Advisor.Enabled && cfg.Advisor.Managed {
		cmd, ep, err := advisor.LaunchManaged(advisor.ManagedSpec{Model: cfg.Advisor.ManagedModel})
		if err != nil {
			log.Printf("advisor: managed mode unavailable (%v) — advisor disabled", err)
			return advisorStack{}
		}
		managed, endpoint, model = cmd, ep, cfg.Advisor.ManagedModel
	}
	sub := advisor.New(advisor.Config{
		Enabled:  cfg.Advisor.Enabled,
		Endpoint: endpoint,
		Model:    model,
		Timeout:  cfg.Advisor.Timeout,
	}, st)
	if sub != nil {
		log.Printf("advisor: local triage enabled via %s (model %q)", endpoint, model)
	} else if managed != nil {
		// Subscriber refused (shouldn't happen post-validation) — don't leave
		// an orphan server behind.
		_ = managed.Process.Kill()
		managed = nil
	}
	return advisorStack{Sub: sub, Managed: managed}
}

// fleetConfigured is true when at least one HMAC fleet webhook can actually
// deliver — the console hides the fleet panel until then.
func fleetConfigured(webhooks []config.WebhookConfig) bool {
	for _, wh := range webhooks {
		if strings.TrimSpace(wh.URL) != "" && strings.TrimSpace(wh.Secret) != "" {
			return true
		}
	}
	return false
}

// buildStatusFn assembles the /status payload from live component state.
// advisorHealth is resolved per call (the advisor stack hot-swaps on config
// reload — a captured bool/subscriber would go stale).
func buildStatusFn(proxyServer *proxy.ProxyServer, tagger *agents.Tagger, cr *correlate.Correlator, eng *firewall.Engine, reg *supervise.Registry, st *store.Store, startTime time.Time, advisorHealth func() advisor.HealthSnapshot, fleetOn, spoolBased bool) api.StatusFunc {
	return func() api.Status {
		proxyActive := proxyServer != nil
		proxyPort := 0
		if proxyServer != nil {
			proxyPort = proxyServer.Port()
		}
		activeAgents := listActiveAgents(tagger)
		// Count tree ROOTS, not processes: a CLI agent with 40 helpers is one
		// agent. (RootPID 0 shouldn't happen but fall back to self.) Infra
		// families (IDEs, model servers) are counted separately — they are
		// shared infrastructure, never agents.
		roots := make(map[int32]struct{}, len(activeAgents))
		infraRoots := make(map[int32]struct{}, len(activeAgents))
		for _, a := range activeAgents {
			r := a.RootPID
			if r == 0 {
				r = a.PID
			}
			if a.Kind == config.AgentKindInfra {
				infraRoots[r] = struct{}{}
				continue
			}
			roots[r] = struct{}{}
		}
		ah := advisorHealth()
		// When file telemetry rides the privileged collector's spool, the
		// daemon probes the writer's real state (launchd service + spool
		// freshness) so posture can report a crash-looping root service the
		// tailer cannot see. Best-effort; nil when not spool-based.
		var esSvc *collect.ESServiceSnapshot
		if spoolBased {
			if snap, err := collect.ESServiceProbe(); err == nil {
				esSvc = &snap
			}
		}
		return api.Status{
			Running:           true,
			Version:           api.Version,
			Uptime:            time.Since(startTime).Truncate(time.Second).String(),
			ActiveAgents:      len(roots),
			InfraCount:        len(infraRoots),
			Coverage:          computeCoverage(activeAgents, st),
			Agents:            activeAgents,
			TrackedProcesses:  len(activeAgents),
			ProxyEnabled:      proxyActive,
			ProxyPort:         proxyPort,
			UninspectedEgress: cr.UninspectedEgressCountWindow(correlate.UninspectedWindow),
			UninspectedInfra:  cr.UninspectedInfraCountWindow(correlate.UninspectedWindow),
			AdvisorEnabled:    ah.Enabled,
			AdvisorHealth:     &ah,
			MutedFlags:        cr.MutedCount(),
			FleetConfigured:   fleetOn,
			FirewallStats:     firewallStats(eng),
			Collectors:        reg.Snapshot(),
			ESService:         esSvc,
		}
	}
}

// coverageWindow is how recent attributed activity must be for a harness to
// count as "seen" — matching the UI's "last activity" staleness signal.
const coverageWindow = 15 * time.Minute

// computeCoverage answers "of the harnesses actually running, how many is
// the daemon seeing?" Active = distinct agent-kind harness names with live
// processes; seen = those with any attributed event inside coverageWindow.
// A harness with zero recent events while its processes run is a harness
// whose hooks are not firing.
func computeCoverage(active []api.AgentSummary, st *store.Store) *api.CoverageStatus {
	if st == nil {
		return nil
	}
	pidsByHarness := make(map[string][]int32)
	for _, a := range active {
		if a.Kind == config.AgentKindInfra {
			continue
		}
		pidsByHarness[a.Name] = append(pidsByHarness[a.Name], a.PID)
	}
	if len(pidsByHarness) == 0 {
		return &api.CoverageStatus{}
	}
	var pids []int32
	for _, list := range pidsByHarness {
		pids = append(pids, list...)
	}
	seen := st.LastEventTimes(pids)
	cutoff := time.Now().Add(-coverageWindow)
	cov := &api.CoverageStatus{HarnessesActive: len(pidsByHarness)}
	for _, list := range pidsByHarness {
		for _, pid := range list {
			if ts, ok := seen[pid]; ok {
				if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil && parsed.After(cutoff) {
					cov.HarnessesSeen++
					break
				}
			}
		}
	}
	return cov
}

func observeResources(tracker *resource.Tracker, tagger *agents.Tagger, st *store.Store, now time.Time) {
	infos := tagger.TaggedPIDs()
	pids := make([]int32, 0, len(infos))
	for pid := range infos {
		pids = append(pids, pid)
	}
	tracker.Observe(infos, st.LastEventTimes(pids), now)
}

const resourceEpisodePendingLimit = 256

type resourceEpisodeStore interface {
	PutResourceEpisode(resource.Episode) error
}

type resourceEpisodeWriter struct {
	recorder *resource.Recorder
	store    resourceEpisodeStore
	mu       sync.Mutex
	pending  map[string]resource.Episode
	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	closed   bool
}

func newResourceEpisodeWriter(st resourceEpisodeStore) *resourceEpisodeWriter {
	w := &resourceEpisodeWriter{
		recorder: resource.NewRecorder(), store: st, pending: make(map[string]resource.Episode),
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *resourceEpisodeWriter) Observe(snapshot resource.Snapshot) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	queued := false
	for _, episode := range w.recorder.Observe(snapshot) {
		key := fmt.Sprintf("%s|%d|%s|%d", episode.Session.Key, episode.CapturedAt.UnixNano(), strings.Join(episode.DiagnosisCodes, ","), episode.Session.RSSBytes)
		if len(w.pending) >= resourceEpisodePendingLimit {
			w.recorder.Retry(episode.Session.Key)
			log.Printf("resource recorder: pending buffer full; will retry session %s", episode.Session.Key)
			continue
		}
		w.pending[key] = episode
		queued = true
	}
	w.mu.Unlock()
	if queued {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

func (w *resourceEpisodeWriter) run() {
	defer close(w.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-w.wake:
			w.flushPending()
		case <-ticker.C:
			w.flushPending()
		case <-w.stop:
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) && w.hasPending() {
				if !w.flushOne() {
					time.Sleep(50 * time.Millisecond)
				}
			}
			return
		}
	}
}

func (w *resourceEpisodeWriter) hasPending() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.pending) > 0
}

func (w *resourceEpisodeWriter) flushPending() {
	for w.flushOne() {
	}
}

func (w *resourceEpisodeWriter) flushOne() bool {
	w.mu.Lock()
	var key string
	var episode resource.Episode
	for key, episode = range w.pending {
		break
	}
	w.mu.Unlock()
	if key == "" {
		return false
	}
	if err := w.store.PutResourceEpisode(episode); err != nil {
		log.Printf("resource recorder: %v; retained for retry", err)
		return false
	}
	w.mu.Lock()
	delete(w.pending, key)
	w.mu.Unlock()
	return true
}

func (w *resourceEpisodeWriter) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.stop)
	w.mu.Unlock()
	select {
	case <-w.done:
	case <-time.After(2500 * time.Millisecond):
		log.Printf("resource recorder: shutdown timed out; abandoning pending writes")
	}
}

func resourcePolicy(c config.ResourceControlConfig) resource.Policy {
	return resource.Policy{
		Mode: resource.ControlMode(c.Mode), MaxRSSBytes: c.MaxRSSMB * 1024 * 1024,
		MaxCPUPercent: c.MaxCPUPercent,
		Sustain:       time.Duration(c.SustainSeconds) * time.Second,
		Cooldown:      time.Duration(c.CooldownSeconds) * time.Second,
		Interventions: resourceInterventions(c.Interventions),
	}
}

func resourceInterventions(steps []config.ResourceInterventionConfig) []resource.InterventionStep {
	out := make([]resource.InterventionStep, 0, len(steps))
	for _, step := range steps {
		out = append(out, resource.InterventionStep{Action: resource.InterventionAction(step.Action),
			After: time.Duration(step.AfterSeconds) * time.Second, Nice: step.Nice})
	}
	return out
}

func resourcePolicySet(c config.ResourceControlConfig) resource.PolicySet {
	set := resource.PolicySet{Default: resourcePolicy(c)}
	for _, override := range c.WorkspaceOverrides {
		set.WorkspaceOverrides = append(set.WorkspaceOverrides, resource.WorkspacePolicy{
			Path: override.CwdPrefix,
			Policy: resource.Policy{
				Mode: resource.ControlMode(override.Mode), MaxRSSBytes: override.MaxRSSMB * 1024 * 1024,
				MaxCPUPercent: override.MaxCPUPercent,
				Sustain:       time.Duration(override.SustainSeconds) * time.Second,
				Cooldown:      time.Duration(override.CooldownSeconds) * time.Second,
				Interventions: resourceInterventions(override.Interventions),
			},
		})
	}
	return set
}

// defaultFleetHeartbeatSec is the status-envelope cadence when
// fleet.heartbeat_interval_sec is unset or zero.
const defaultFleetHeartbeatSec = 60

// fleetTransitionCheckSec is how often the heartbeat loop re-derives posture
// looking for state transitions. A node going critical must not wait out a
// full heartbeat interval to tell the collector.
const fleetTransitionCheckSec = 15

// buildFleetSinks constructs one signed sink per configured webhook; entries
// missing url or secret are skipped loudly, never silently dropped. Shared by
// startup and the config hot-reload watcher.
func buildFleetSinks(fc config.FleetConfig, logDir string) []*fleet.Sink {
	sinks := []*fleet.Sink{}
	for i, wh := range fc.Webhooks {
		sink := fleet.NewSink(wh, api.NodeID, api.Version, logDir)
		if sink == nil {
			log.Printf("fleet: webhook #%d disabled (missing url or secret)", i)
			continue
		}
		sinks = append(sinks, sink)
	}
	return sinks
}

// fleetConfigHolder is the atomic, swap-safe fleet config the heartbeat loop
// reads per cycle — config hot-reload swaps it alongside the sink set, so an
// interval/labels/hostname edit takes effect without a daemon restart.
type fleetConfigHolder struct{ v atomic.Value } // config.FleetConfig

func (h *fleetConfigHolder) Load() config.FleetConfig {
	if x := h.v.Load(); x != nil {
		return x.(config.FleetConfig)
	}
	return config.FleetConfig{}
}

func (h *fleetConfigHolder) Store(c config.FleetConfig) { h.v.Store(c) }

// buildNodeStatus assembles the heartbeat payload from the same posture +
// status the local UIs render (pure — directly unit-testable).
func buildNodeStatus(st api.Status, p api.Posture, hostname string, labels map[string]string, budget resource.BudgetSummary) model.NodeStatus {
	return model.NodeStatus{
		Hostname:       hostname,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Agents:         st.ActiveAgents,
		Uptime:         st.Uptime,
		PostureState:   p.State,
		PostureSummary: p.Summary,
		NeedsYou:       p.NeedsYou,
		Labels:         labels,
		Budget: &model.BudgetStatus{
			Mode: string(budget.Mode), Enforced: budget.Enforced,
			OverBudget: budget.OverBudget, Approval: budget.Approval,
			Contained: budget.Contained, Paused: budget.Paused,
		},
	}
}

// startFleetHeartbeat pushes a status envelope (liveness + posture headline)
// to every configured sink: once at boot, then on a ticker, and immediately
// whenever the posture STATE changes (all-clear → critical must not wait out
// the interval). The loop ALWAYS runs — unfleeted nodes skip the publish but
// keep tracking posture state, so enrolling a collector at runtime (config
// hot-reload) activates heartbeats without a restart and without a spurious
// "transition" for a state the node was already in. Heartbeats bypass
// per-sink kind filters on purpose: liveness that can be unsubscribed is
// indistinguishable from a dead node.
func startFleetHeartbeat(ctx context.Context, apiServer *api.API, statusFn api.StatusFunc, pub *fleet.Publisher, cfgGet func() config.FleetConfig) {
	if pub == nil {
		return
	}
	push := func() string {
		p := apiServer.CurrentPosture()
		if !pub.HasSinks() {
			return p.State
		}
		fc := cfgGet()
		hostname := fc.Hostname
		if hostname == "" {
			hostname, _ = os.Hostname()
		}
		pub.Publish(fleet.EventStatus, buildNodeStatus(statusFn(), p, hostname, fc.Labels, apiServer.BudgetSummary()))
		return p.State
	}
	interval := func() time.Duration {
		if d := time.Duration(cfgGet().HeartbeatIntervalSec) * time.Second; d > 0 {
			return d
		}
		return defaultFleetHeartbeatSec * time.Second
	}
	go fleetHeartbeatLoop(ctx, push, func() string { return apiServer.CurrentPosture().State },
		interval, fleetTransitionCheckSec*time.Second)
	log.Printf("fleet: status heartbeat armed (cadence from fleet.heartbeat_interval_sec, default %ds)", defaultFleetHeartbeatSec)
}

// fleetHeartbeatLoop pushes once immediately, then on the heartbeat timer,
// and immediately whenever the posture state changes between transition
// checks. The interval is re-read on every fire (config hot-reload).
// Extracted from startFleetHeartbeat so tests can run it with millisecond
// cadences.
func fleetHeartbeatLoop(ctx context.Context, push func() string, stateFn func() string, interval func() time.Duration, transitionCheck time.Duration) {
	lastState := push()
	transition := time.NewTicker(transitionCheck)
	defer transition.Stop()
	heartbeat := time.NewTimer(interval())
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			lastState = push()
			heartbeat.Reset(interval())
		case <-transition.C:
			if s := stateFn(); s != lastState {
				lastState = push()
			}
		}
	}
}

// watchParentExit returns a channel that closes when the daemon's owning
// parent changes (i.e. the menu bar app died and we were reparented to
// launchd). Returns nil when launched directly by pid 1 — no owning parent
// to outlive, so no watch is needed.
func watchParentExit(initialPPID int) <-chan struct{} {
	if initialPPID == 1 {
		return nil
	}
	parentGone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if os.Getppid() != initialPPID {
				log.Printf("secure-agentd: owning parent (pid %d) exited; shutting down", initialPPID)
				close(parentGone)
				return
			}
		}
	}()
	return parentGone
}
