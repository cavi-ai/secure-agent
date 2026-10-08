package main

import (
	"context"
	"errors"
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
		"run ONLY the ES collector: spawn eslogger and write its output to the spool (/var/db/secure-agent/es-spool.jsonl). Also selected when the binary runs as "+esCollectorName+".")
	flag.Parse()

	// The privileged ES-collector mode reuses THIS binary: the app bundle
	// ships it a second time as secure-agent-esd and registers that copy as
	// a LaunchDaemon, so the Endpoint Security client runs under the app's
	// identity and the app's one Full Disk Access grant.
	if isESCollectorInvocation(os.Args[0], *esCollector) {
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
	cfg, overlayErr, err := config.LoadWithOverlay(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lock, err := daemon.LockInstance(ctx, cfg.DBPath)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, daemon.ErrParentGone) {
			log.Printf("secure-agentd: stopped while waiting for the instance lock: %v", err)
			return
		}
		log.Fatalf("failed to start daemon: %v", err)
	}
	defer lock.Release()

	// Build is the composition root: it resolves every component from cfg and
	// starts the collectors and servers. main() is CLI parsing plus process
	// lifecycle only.
	comps, err := daemon.Build(ctx, cfg, daemon.Options{ConfigPath: configPathUsed, ConfigOverlayErr: overlayErr})
	if err != nil {
		log.Fatalf("failed to start daemon: %v", err)
	}

	// Exit when the owning parent (the menubar app) goes away, or on a signal.
	runErr := comps.WaitForShutdown(ctx)
	comps.Shutdown()
	if runErr != nil {
		log.Fatalf("daemon stopped: %v", runErr)
	}
}
