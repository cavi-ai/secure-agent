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
	flag.Parse()

	log.Println("starting secure-agentd daemon...")

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
	advisorSub := setupAdvisor(cfg, st)

	// Drain bus and correlate/persist (drainDone closes once every delivered
	// event has been persisted — shutdown waits for it).
	drainDone := startDrainLoop(b.Subscribe(), st, correlator, fleetPub, advisorSub)

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

	var proxyServer *proxy.ProxyServer
	if cfg.ProxyEnabled {
		proxyServer = setupProxy(cfg, b, fw.Engine)
	}

	// Supervisor with a shared health registry so /status reports each collector's
	// real state (running / restarting / abandoned) instead of a blanket "running".
	supReg := supervise.NewRegistry()
	sup := supervise.New(supReg)

	statusFn := buildStatusFn(proxyServer, tagger, correlator, fw.Engine, supReg, time.Now())

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

	if collect.ESLoggerAvailable() {
		go sup.Run(ctx, "eslogger", func(c context.Context) error {
			es := collect.NewESLogger(b)
			return es.Run(c)
		})
	} else {
		// Non-macOS (or eslogger not installed): file-activity telemetry is
		// degraded, not crash-looped. The transcript scanner still covers the
		// hook activity log, so guard/plugin signals keep flowing.
		log.Printf("eslogger unavailable on this platform; Endpoint Security telemetry disabled (transcript + network signals still active)")
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

	if advisorSub != nil {
		go sup.Run(ctx, "advisor", func(c context.Context) error {
			return advisorSub.Run(c)
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
		res = append(res, api.AgentSummary{
			PID:     pid,
			Name:    info.Name,
			ExePath: info.ExePath,
			CWD:     info.CWD,
		})
	}
	return res
}
