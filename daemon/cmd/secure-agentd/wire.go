package main

import (
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agentenv"
	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
	"github.com/cavi-ai/secure-agent/daemon/internal/proxy"
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
// harness's activity logs plus the daemon's own JSONL sink when configured.
func transcriptTailTargets(home, jsonlPath string) []string {
	targets := []string{
		filepath.Join(home, ".claude", "logs", "*.jsonl"),
		filepath.Join(home, ".claude", "projects"),
		filepath.Join(home, ".cursor", "logs", "*.jsonl"),
		filepath.Join(home, ".local", "state", "secure-agent", "activity.jsonl"),
	}
	if jsonlPath != "" {
		targets = append(targets, jsonlPath)
	}
	return targets
}

// startDrainLoop consumes the bus, persisting events and correlating flags →
// incidents → fleet webhooks. The returned channel closes once every delivered
// event has been persisted, so shutdown can wait for it instead of dropping
// the final, most-relevant events/flags/incident around a kill or quit.
// adv may be nil (advisor disabled); when set, new flags/incidents are also
// offered for advisory triage — enqueueing is non-blocking and drop-safe.
func startDrainLoop(sub <-chan event.Event, st *store.Store, cr *correlate.Correlator, pub *fleet.Publisher, adv *advisor.Subscriber) <-chan struct{} {
	analyzer := intel.NewAnalyzer()
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for e := range sub {
			st.PutEvent(e)
			flags := cr.Observe(e)
			for _, fl := range flags {
				log.Printf("FLAG TRIGGERED [%d]: %s (pid %d agent %s)", fl.Severity, fl.Rule, fl.PID, fl.Agent)
				st.PutFlag(fl)
				pub.Publish(fleet.EventFlag, fl)
				if adv != nil {
					adv.EnqueueFlag(fl)
				}

				recentEvs := st.RecentEvents(100)
				report := analyzer.Analyze(fl, recentEvs)
				st.PutIncident(report)
				log.Printf("INCIDENT CREATED [%s]: %s (Risk: %s, %d rotate items)", report.ID, report.Summary, report.Risk, len(report.RotateList))
				pub.Publish(fleet.EventIncident, report)
				if adv != nil {
					adv.EnqueueIncident(report)
				}
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

// buildStatusFn assembles the /status payload from live component state.
func buildStatusFn(proxyServer *proxy.ProxyServer, tagger *agents.Tagger, cr *correlate.Correlator, eng *firewall.Engine, reg *supervise.Registry, startTime time.Time, advisorEnabled bool) api.StatusFunc {
	return func() api.Status {
		proxyActive := proxyServer != nil
		proxyPort := 0
		if proxyServer != nil {
			proxyPort = proxyServer.Port()
		}
		activeAgents := listActiveAgents(tagger)
		// Count tree ROOTS, not processes: a CLI agent with 40 helpers is one
		// agent. (RootPID 0 shouldn't happen but fall back to self.)
		roots := make(map[int32]struct{}, len(activeAgents))
		for _, a := range activeAgents {
			r := a.RootPID
			if r == 0 {
				r = a.PID
			}
			roots[r] = struct{}{}
		}
		return api.Status{
			Running:           true,
			Version:           api.Version,
			Uptime:            time.Since(startTime).Truncate(time.Second).String(),
			ActiveAgents:      len(roots),
			Agents:            activeAgents,
			TrackedProcesses:  len(activeAgents),
			ProxyEnabled:      proxyActive,
			ProxyPort:         proxyPort,
			UninspectedEgress: cr.UninspectedEgressCount(),
			AdvisorEnabled:    advisorEnabled,
			MutedFlags:        cr.MutedCount(),
			FirewallStats:     firewallStats(eng),
			Collectors:        reg.Snapshot(),
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
