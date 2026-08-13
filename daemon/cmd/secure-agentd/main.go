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

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
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

	var proxyServer *proxy.ProxyServer
	if cfg.ProxyEnabled {
		caMgr, err := proxy.NewCAManager(cfg.ProxyCACertPath, cfg.ProxyCAKeyPath)
		if err != nil {
			log.Printf("Failed to initialize Proxy CA Manager: %v", err)
		} else {
			proxyServer = proxy.NewProxyServer(cfg.ProxyPort, b, caMgr)
		}
	}

	startTime := time.Now()
	statusFn := func() api.Status {
		proxyActive := proxyServer != nil
		proxyPort := 0
		if proxyServer != nil {
			proxyPort = proxyServer.Port()
		}
		return api.Status{
			Running:      true,
			Uptime:       time.Since(startTime).Truncate(time.Second).String(),
			ActiveAgents: countActiveAgents(tagger),
			ProxyEnabled: proxyActive,
			ProxyPort:    proxyPort,
		}
	}

	// Start Control API
	apiServer := api.New(cfg.SocketPath, st, &realKiller{}, statusFn)
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
	<-sigCh

	log.Println("secure-agentd shutting down...")
	cancel()
	time.Sleep(200 * time.Millisecond)
}

func countActiveAgents(tg *agents.Tagger) int {
	return len(tg.TaggedPIDs())
}
