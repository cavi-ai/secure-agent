package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/proxy"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

type realKiller struct{}

func (k *realKiller) Kill(pid int32) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	log.Printf("secure-agentd: issuing SIGKILL to pid %d", pid)
	return syscall.Kill(int(pid), syscall.SIGKILL)
}

func main() {
	configPath := flag.String("config", "", "path to config.yaml overlay")
	esCollector := flag.Bool("es-collector", false,
		"run ONLY the ES collector: spawn eslogger and write its output to the spool (/var/db/secure-agent/es-spool.jsonl). Used by the root LaunchDaemon so the FDA grant already held by THIS binary covers the ES client — no separate drag step.")
	flag.Parse()

	// The privileged ES-collector mode reuses THIS binary (which the operator
	// already granted Full Disk Access in Settings) so the Endpoint Security
	// client is created by a process macOS already trusts — that's the whole
	// point of the "one FDA grant covers everything" UX.
	if *esCollector {
		if err := runESCollector(); err != nil {
			log.Fatalf("es-collector: %v", err)
		}
		return
	}

	log.Println("starting secure-agentd daemon...")

	configPathUsed := *configPath
	if configPathUsed == "" {
		if home, err := os.UserHomeDir(); err == nil {
			if _, err := os.Stat(filepath.Join(home, ".config", "secure-agent", "config.yaml")); err == nil {
				configPathUsed = filepath.Join(home, ".config", "secure-agent", "config.yaml")
			}
		}
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Serialize per-project guard policies for the stdlib-only hook to read.
	if err := config.WriteCwdOverrides(config.DefaultCwdOverridesPath(), cfg.DirectoryGuard.CwdOverrides); err != nil {
		log.Printf("failed to write guard cwd overrides: %v", err)
	}

	st, err := store.Open(cfg.DBPath, cfg.JSONLPath)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	defer st.Close()

	b := bus.New(2048)
	defer b.Close()

	procSource := agents.NewProcSource()
	tagger := agents.New(cfg, procSource)
	tagger.Refresh()

	classifier := sensitive.New(cfg)
	correlator := correlate.New(tagger, classifier, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Stable per-install fleet identity (used by /fleet and webhook payloads).
	// Must run before the sinks are built: they capture api.NodeID.
	api.LoadNodeID(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "node-id"))

	// Fleet webhook fan-out: flags, incidents, and guard decisions are pushed
	// to every configured HMAC-signed collector. Best-effort; never blocks the
	// drain loop.
	fleetPub := fleet.NewPublisher()
	for i, wh := range cfg.Fleet.Webhooks {
		sink := fleet.NewSink(wh, api.NodeID, api.Version, filepath.Dir(cfg.DBPath))
		if sink == nil {
			log.Printf("fleet: webhook #%d disabled (missing url or secret)", i)
			continue
		}
		fleetPub.AddSink(sink)
	}

	// Local triage advisor (opt-in): flags/incidents are offered to it from
	// the drain loop; it never touches the enforcement path.
	advisorStk := &advisorStackHolder{}
	advisorStk.Store(setupAdvisor(cfg, st))

	// Hot-reload: the menubar edits config.yaml on every advisor/settings
	// change; the daemon must NOT require a relaunch. Watch the file and
	// swap the advisor stack live when it changes (disable/enable/model
	// switch apply within a poll cycle; guard modes read per-request already).
	if configPathUsed != "" {
		go watchAdvisorConfig(ctx, configPathUsed, st, advisorStk)
	}

	// Drain bus and correlate/persist (drainDone closes once every delivered
	// event has been persisted — shutdown waits for it).
	drainDone := startDrainLoop(b.Subscribe(), st, correlator, fleetPub, func() *advisor.Subscriber { return advisorStk.Load().Sub })

	// Periodic process tagger refresh (1s)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tagger.Refresh()
			}
		}
	}()

	// Firewall engine + persisted overrides, used by the proxy for egress
	// inspection and surfaced as per-rule stats in status.
	fw := setupFirewall(cfg)

	// User-approved allowlist additions (console egress suggestions): persisted
	// beside the other override state and consulted on every vendor check.
	allowlistStore := correlate.NewAllowlistStore(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "allowlist-overrides.json"))
	correlator.SetAllowlistOverrides(func(agent string) []string { return allowlistStore.Load()[agent] })

	// Operator dispositions (mute rule+host): persisted likewise; muted pairs
	// are counted, not flagged.
	muteStore := correlate.NewMuteStore(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "muted.json"))
	correlator.SetMuteChecker(func(rule, host string) bool {
		for _, h := range muteStore.Load()[rule] {
			if h == host {
				return true
			}
		}
		return false
	})

	// Advisor pre-assessment of suggestion-threshold hosts: when an endpoint
	// crosses into suggestion territory, the advisor has its legitimacy
	// verdict ready before the operator opens the console.
	// Register the host-assessment hook unconditionally, but resolve the
	// subscriber per call: config hot-reload swaps (or disables) the stack,
	// and a callback captured when the advisor was enabled must NEVER call
	// into a now-nil subscriber after a disable (the panic that took the
	// daemon down during the hot-reload smoke).
	correlator.SetOnUninspected(func(agent, host string) {
		if sub := advisorStk.Load().Sub; sub != nil {
			sub.EnqueueHost(agent, host)
		}
	})

	var proxyServer *proxy.ProxyServer
	if cfg.ProxyEnabled {
		proxyServer = setupProxy(cfg, b, fw.Engine)
	}

	// Supervisor with a shared health registry so /status reports each collector's
	// real state (running / restarting / abandoned) instead of a blanket "running".
	supReg := supervise.NewRegistry()
	sup := supervise.New(supReg)

	statusFn := buildStatusFn(proxyServer, tagger, correlator, fw.Engine, supReg, time.Now(), cfg.Advisor.Enabled)

	// Start Control API
	apiServer := api.New(cfg.SocketPath, st, &realKiller{}, statusFn)

	// Peer-credential gating on the control socket: kernel-attested pid/uid per
	// connection. Owner uid gets reads, tagged agent pids may ask the guard for
	// decisions. /kill is restricted to recognized agent processes regardless of
	// caller. The owning app (the menubar that launched this daemon) is pinned
	// as the only mutating client; direct launches (ppid = shell) keep
	// owner-uid mutation so headless/ssh management still works.
	agentPIDSet := apiServer_taggedPIDs(tagger)
	apiServer.SetPeers(api.NewPeerChecker(), agentPIDSet)
	apiServer.SetAgentPIDs(agentPIDSet)
	// Pin the owning menubar app as the only mutating client — but only when
	// the parent really is an .app binary. A direct launch from a shell must
	// keep owner-uid mutation (headless/ssh management); pinning the shell
	// would lock the CLI out of resolve/firewall while granting the shell UI
	// powers. ps(1) is spawned once at startup, not per request.
	if ppid := os.Getppid(); ppid > 1 {
		if out, err := exec.Command("ps", "-p", strconv.Itoa(ppid), "-o", "comm=").Output(); err == nil {
			parentExe := strings.TrimSpace(string(out))
			if strings.Contains(parentExe, ".app/Contents/MacOS/") || strings.Contains(parentExe, ".app/Contents/Frameworks/") {
				apiServer.SetUIPID(int32(ppid))
			}
		}
	}

	apiServer.SetFirewall(api.FirewallControl{
		Engine:      fw.Engine,
		Modes:       fw.Modes,
		Reload:      fw.Reload,
		Ingest:      fw.Ingest,
		Sources:     fw.Sources,
		BaseSources: fw.BaseSources,
	})

	guardBroker := guard.NewBroker(time.Duration(guardBrokerMS(cfg.DirectoryGuard.PromptDeadlineMS)) * time.Millisecond)
	apiServer.SetGuard(guardBroker)
	apiServer.SetAllowlist(correlator, allowlistStore)
	apiServer.SetMute(correlator, muteStore)
	apiServer.SetFleetSink(fleetPub)
	// SSE live feed: each console gets its own bus subscription; unsubscribes
	// when the connection closes.
	apiServer.SetEventStream(b.Subscribe, b.Unsubscribe)
	apiServer.SetEventPublisher(b.Publish)

	// The browser console's telemetry fetches are same-origin with the
	// dashboard, i.e. they land on the proxy's loopback HTTP port. Serve the
	// API there behind the console token (a credential agents never receive —
	// unlike the proxy token they carry for egress), so /dashboard/ shows live
	// data instead of a wall of 407s.
	if proxyServer != nil {
		consoleToken := proxy.LoadConsoleToken(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "console-token"))
		if consoleToken == "" {
			log.Printf("WARNING: console token unavailable; browser console API on the proxy port is disabled")
		}
		proxyServer.SetConsoleAPI(apiServer.ConsoleHandler())
	}
	go func() {
		if err := apiServer.Serve(ctx); err != nil && ctx.Err() == nil {
			log.Printf("API server error: %v", err)
		}
	}()

	// Supervised collectors
	if proxyServer != nil {
		go sup.Run(ctx, "proxyserver", func(c context.Context) error {
			return proxyServer.Serve(c)
		})
	}

	// File-activity telemetry, in order of preference:
	//  1. Spool tail: the privileged ES collector (root LaunchDaemon) writes
	//     eslogger output to /var/db/secure-agent/es-spool.jsonl; we tail it.
	//     This is the sanctioned architecture — macOS permits ES clients only
	//     as root, and this daemon deliberately runs unprivileged.
	//  2. Direct eslogger child: only works when this daemon runs as root
	//     (dev / explicit-sudo runs); on a user daemon it fails NOT_PRIVILEGED
	//     permanently on the first try.
	//  3. Neither: file telemetry is degraded, not crash-looped. The
	//     transcript scanner still covers the hook activity log.
	switch {
	case collect.SpoolAvailable():
		go sup.Run(ctx, "eslogger", func(c context.Context) error {
			t := collect.NewSpoolTailer(b)
			return t.Run(c)
		})
		log.Printf("file telemetry: tailing privileged ES collector spool")
	case os.Geteuid() == 0 && collect.ESLoggerAvailable():
		go sup.Run(ctx, "eslogger", func(c context.Context) error {
			es := collect.NewESLogger(b)
			return es.Run(c)
		})
	default:
		log.Printf("file telemetry unavailable: ES requires a privileged collector (install it from Settings); transcript + network signals still active")
	}

	go sup.Run(ctx, "netsampler", func(c context.Context) error {
		ns := collect.NewNetSampler(b, tagger, cfg.NetSampleInterval, nil)
		return ns.Run(c)
	})

	home, _ := os.UserHomeDir()
	go sup.Run(ctx, "transcript", func(c context.Context) error {
		ts := collect.NewTranscriptScanner(b, transcriptTailTargets(home, cfg.JSONLPath))
		return ts.Run(c)
	})

	if advisorStk.Load().Sub != nil {
		go sup.Run(ctx, "advisor", func(c context.Context) error {
			return advisorStk.Load().Sub.Run(c)
		})
	}
	if advisorStk.Load().Managed != nil {
		// The managed model server as a supervised collector: restart on
		// crash like any other, and kill it on shutdown so it never outlives
		// the daemon (advisor verdicts die with the app, by design).
		go sup.Run(ctx, "advisor-model", func(c context.Context) error {
			done := make(chan error, 1)
			go func() { done <- advisorStk.Load().Managed.Wait() }()
			select {
			case <-c.Done():
				_ = advisorStk.Load().Managed.Process.Kill()
				return nil
			case err := <-done:
				return err
			}
		})
	}

	log.Printf("secure-agentd running on unix socket %s", cfg.SocketPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Exit when orphaned. The menu bar app that launches this daemon owns its
	// lifetime and sends SIGTERM on quit. If that app dies abruptly (even via
	// SIGKILL, which cannot be caught by it), this process is reparented to
	// launchd (pid 1). Watching for the parent changing guarantees the daemon
	// never lingers as a hidden background process after its owner is gone.
	// watchParentExit returns nil when launched directly by pid 1, where there
	// is no owning parent to outlive.
	parentGone := watchParentExit(os.Getppid())

	select {
	case <-sigCh:
	case <-parentGone:
	}

	log.Println("secure-agentd shutting down...")
	cancel()  // stop collectors, API, and the tagger loop
	b.Close() // close the subscriber channel so the drain goroutine finishes buffered events
	select {
	case <-drainDone: // all delivered events persisted
	case <-time.After(2 * time.Second): // bounded: never hang shutdown on a stuck write
		log.Println("secure-agentd: drain timed out; some buffered events may be unpersisted")
	}
	// Give in-flight webhook deliveries a bounded window to land — a fleet
	// collector must not lose the final events to process exit.
	fleetDone := make(chan struct{})
	go func() { fleetPub.Wait(); close(fleetDone) }()
	select {
	case <-fleetDone:
	case <-time.After(3 * time.Second):
		log.Println("secure-agentd: webhook delivery wait timed out; some deliveries may be dropped")
	}
}

func firewallStats(e *firewall.Engine) map[string]firewall.RuleStat {
	if e == nil {
		return nil
	}
	return e.Stats()
}

// apiServer_taggedPIDs adapts the tagger's pid map to the API's allowlist
// shape. Shared by peer classification and /kill restriction.
func apiServer_taggedPIDs(tg *agents.Tagger) func() map[int32]struct{} {
	return func() map[int32]struct{} {
		tagged := tg.TaggedPIDs()
		pids := make(map[int32]struct{}, len(tagged))
		for pid := range tagged {
			pids[pid] = struct{}{}
		}
		return pids
	}
}

func listActiveAgents(tg *agents.Tagger) []api.AgentSummary {
	tagged := tg.TaggedPIDs()
	res := make([]api.AgentSummary, 0, len(tagged))
	for pid, info := range tagged {
		s := api.AgentSummary{
			PID:      pid,
			Name:     info.Name,
			ExePath:  info.ExePath,
			CWD:      info.CWD,
			PPID:     info.PPID,
			RootPID:  info.RootPID,
			RSSBytes: info.RSSBytes,
			IsOrphan: info.IsOrphan,
		}
		if !info.StartedAt.IsZero() {
			s.StartedAt = info.StartedAt.UTC().Format(time.RFC3339)
		}
		res = append(res, s)
	}
	return res
}
