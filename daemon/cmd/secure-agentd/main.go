package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/daemon"
)

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
			if IsESPermanentFailure(err) {
				// Exit 0: the refusal cannot clear on respawn (wrong user,
				// tampered binary, missing eslogger), and a nonzero exit
				// would let launchd respawn the refusal forever.
				log.Printf("es-collector: %v — refusing permanently, service stays stopped", err)
				return
			}
			log.Fatalf("es-collector: %v", err)
		}
		return
	}

	log.Println("starting secure-agentd daemon...")

	configPathUsed := *configPath
	if configPathUsed == "" {
		if home, err := os.UserHomeDir(); err == nil {
			configPathUsed = filepath.Join(home, ".config", "secure-agent", "config.yaml")
		}
	}
	configPathUsed = config.ExpandPath(configPathUsed)
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Build is the composition root: it resolves every component from cfg and
	// starts the collectors and servers. main() is CLI parsing plus process
	// lifecycle only.
	comps, err := daemon.Build(ctx, cfg, daemon.Options{ConfigPath: configPathUsed})
	if err != nil {
		log.Fatalf("failed to start daemon: %v", err)
	}

	// Exit when the owning parent (the menubar app) goes away, or on a signal.
	comps.WaitForShutdown(ctx)
	comps.Shutdown()
}
