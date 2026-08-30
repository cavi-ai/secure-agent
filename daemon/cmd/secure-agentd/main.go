package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agentenv"
	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/intel"
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

	st, err := store.Open(cfg.DBPath, cfg.JSONLPath)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	defer st.Close()

	b := bus.New(2048)
	defer b.Close()

	procSource := agents.NewDarwinProcSource()
	tagger := agents.New(cfg, procSource)
	tagger.Refresh()

	classifier := sensitive.New(cfg)
	correlator := correlate.New(tagger, classifier, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Drain bus and correlate/persist
	sub := b.Subscribe()
	analyzer := intel.NewAnalyzer()
	go func() {
		for e := range sub {
			st.PutEvent(e)
			flags := correlator.Observe(e)
			for _, fl := range flags {
				log.Printf("FLAG TRIGGERED [%d]: %s (pid %d agent %s)", fl.Severity, fl.Rule, fl.PID, fl.Agent)
				st.PutFlag(fl)

				recentEvs := st.RecentEvents(100)
				report := analyzer.Analyze(fl, recentEvs)
				st.PutIncident(report)
				log.Printf("INCIDENT CREATED [%s]: %s (Risk: %s, %d rotate items)", report.ID, report.Summary, report.Risk, len(report.RotateList))
			}
		}
	}()

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

	// Firewall engine: built once, used by the proxy for egress inspection and
	// surfaced as per-rule stats in status.
	fwSalt, _ := firewall.LoadSalt(cfg.Firewall.Registry.SaltRef)
	fwEngine, fwErr := firewall.NewEngine(cfg.Firewall, fwSalt)
	if fwErr != nil {
		log.Printf("Failed to initialize firewall engine: %v", fwErr)
	}
	// Apply any persisted rule-mode overrides (e.g. rules promoted to block in a
	// previous session) on top of the config defaults.
	fwModes := firewall.NewModeStore(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "firewall-modes.json"))
	if fwEngine != nil {
		for rule, mode := range fwModes.Load() {
			fwEngine.SetRuleMode(rule, firewall.ParseMode(mode))
		}
	}

	// Known-secret fingerprints: config defaults plus any registered by
	// `secure-agent fingerprint`. Reapplied on demand via /firewall/fingerprints/reload.
	fpStore := firewall.NewFingerprintStore(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "firewall-fingerprints.json"))

	// User-added ingest sources (registered from the console) persist alongside
	// the mode and fingerprint overrides, so a source survives a restart without
	// editing the config overlay.
	srcStore := firewall.NewSourceStore(filepath.Join(filepath.Dir(cfg.Firewall.Registry.SaltRef), "firewall-sources.json"))
	reloadFingerprints := func() error {
		combined := append(append([]config.Fingerprint{}, cfg.Firewall.Registry.Fingerprints...), fpStore.Load()...)
		if fwEngine != nil {
			fwEngine.SetFingerprints(combined)
		}
		return nil
	}
	_ = reloadFingerprints() // apply persisted fingerprints on startup

	// ingestFingerprints scans the configured secret sources, registers their
	// HMAC fingerprints, and applies them live. Triggered by `secure-agent
	// fingerprint`.
	ingestFingerprints := func() ([]string, error) {
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
		_ = reloadFingerprints()
		labels := make([]string, 0, len(fps))
		for _, fp := range fps {
			labels = append(labels, fp.Label)
		}
		return labels, nil
	}

	var proxyServer *proxy.ProxyServer
	if cfg.ProxyEnabled {
		caMgr, err := proxy.NewCAManager(cfg.ProxyCACertPath, cfg.ProxyCAKeyPath)
		if err != nil {
			log.Printf("Failed to initialize Proxy CA Manager: %v", err)
		} else {
			proxyServer = proxy.NewProxyServer(cfg.ProxyPort, b, caMgr, fwEngine)
			// Write the opt-in routing snippet into our own config dir. It does
			// nothing until the user sources it; we never edit their shell rc.
			if snippetPath, werr := agentenv.WriteSnippet(filepath.Dir(cfg.ProxyCACertPath), cfg.ProxyPort, cfg.ProxyCACertPath); werr == nil {
				log.Printf("agent routing snippet: %s (source it to route agents through the proxy)", snippetPath)
			}
		}
	}

	startTime := time.Now()
	statusFn := func() api.Status {
		proxyActive := proxyServer != nil
		proxyPort := 0
		if proxyServer != nil {
			proxyPort = proxyServer.Port()
		}
		activeAgents := listActiveAgents(tagger)
		return api.Status{
			Running:           true,
			Uptime:            time.Since(startTime).Truncate(time.Second).String(),
			ActiveAgents:      len(activeAgents),
			Agents:            activeAgents,
			ProxyEnabled:      proxyActive,
			ProxyPort:         proxyPort,
			UninspectedEgress: correlator.UninspectedEgressCount(),
			FirewallStats:     firewallStats(fwEngine),
		}
	}

	// Start Control API
	apiServer := api.New(cfg.SocketPath, st, &realKiller{}, statusFn)
	apiServer.SetFirewall(api.FirewallControl{
		Engine:      fwEngine,
		Modes:       fwModes,
		Reload:      reloadFingerprints,
		Ingest:      ingestFingerprints,
		Sources:     srcStore,
		BaseSources: cfg.Firewall.Registry.IngestSources,
	})
	go func() {
		if err := apiServer.Serve(ctx); err != nil && ctx.Err() == nil {
			log.Printf("API server error: %v", err)
		}
	}()

	// Tail targets for transcript scanner
	home, _ := os.UserHomeDir()
	tailTargets := []string{
		filepath.Join(home, ".claude", "logs", "*.jsonl"),
		filepath.Join(home, ".claude", "projects"),
		filepath.Join(home, ".cursor", "logs", "*.jsonl"),
		filepath.Join(home, ".local", "state", "secure-agent", "activity.jsonl"),
	}
	if cfg.JSONLPath != "" {
		tailTargets = append(tailTargets, cfg.JSONLPath)
	}

	// Supervised collectors
	if proxyServer != nil {
		go supervise.Run(ctx, "proxyserver", func(c context.Context) error {
			return proxyServer.Serve(c)
		})
	}

	go supervise.Run(ctx, "eslogger", func(c context.Context) error {
		es := collect.NewESLogger(b)
		return es.Run(c)
	})

	go supervise.Run(ctx, "netsampler", func(c context.Context) error {
		ns := collect.NewNetSampler(b, tagger, cfg.NetSampleInterval, nil)
		return ns.Run(c)
	})

	go supervise.Run(ctx, "transcript", func(c context.Context) error {
		ts := collect.NewTranscriptScanner(b, tailTargets)
		return ts.Run(c)
	})

	log.Printf("secure-agentd running on unix socket %s", cfg.SocketPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Exit when orphaned. The menu bar app that launches this daemon owns its
	// lifetime and sends SIGTERM on quit. If that app dies abruptly (even via
	// SIGKILL, which cannot be caught by it), this process is reparented to
	// launchd (pid 1). Watching for the parent changing guarantees the daemon
	// never lingers as a hidden background process after its owner is gone.
	// Skip the watch when launched directly by pid 1 (launchd or an already
	// orphaned context), where there is no owning parent to outlive.
	parentGone := make(chan struct{})
	if initialPPID := os.Getppid(); initialPPID != 1 {
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
	}

	select {
	case <-sigCh:
	case <-parentGone:
	}

	log.Println("secure-agentd shutting down...")
	cancel()
	time.Sleep(200 * time.Millisecond)
}

func firewallStats(e *firewall.Engine) map[string]firewall.RuleStat {
	if e == nil {
		return nil
	}
	return e.Stats()
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
