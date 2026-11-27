package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/daemon"
)

func main() {
	configPath := flag.String("config", "", "path to config.yaml overlay")
	ownerPIDVersion := flag.Uint("owner-pid-version", 0, "owning app audit-token process version")
	reportOwnerSocket := flag.Bool("report-owner-socket", false, "report the bound control socket to the owning app via the inherited socket on fd 0")
	esCollector := flag.Bool("es-collector", false,
		"run ONLY the ES collector: spawn eslogger and write its output to the spool (/var/db/secure-agent/es-spool.jsonl). Also selected when the binary runs as "+esCollectorName+".")
	flag.Parse()
	if *ownerPIDVersion > 1<<32-1 {
		log.Fatal("invalid owning app process version")
	}

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

	if *reportOwnerSocket && *ownerPIDVersion == 0 {
		log.Fatal("reporting the control socket requires an owning app")
	}

	log.Println("starting secure-agentd daemon...")

	configPathUsed := *configPath
	if configPathUsed == "" {
		configPathUsed = config.DefaultConfigPath()
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

	var headless *daemon.InstanceLock
	if *ownerPIDVersion == 0 {
		headless, err = daemon.LockHeadless(cfg.SocketPath)
		if err != nil {
			log.Fatalf("failed to start daemon: failed to bind control API: %v", err)
		}
		defer headless.Release()
	}

	// Build starts collectors and servers only after socket ownership is held.
	comps, err := daemon.Build(ctx, cfg, daemon.Options{ConfigPath: configPathUsed, ConfigOverlayErr: overlayErr, OwnerPIDVersion: uint32(*ownerPIDVersion)})
	if err != nil {
		log.Fatalf("failed to start daemon: %v", err)
	}

	if *reportOwnerSocket {
		if err := reportControlSocket(cfg.SocketPath); err != nil {
			log.Printf("secure-agentd: could not report control socket to owning app: %v", err)
		}
		os.Stdin.Close()
	}

	// Exit when the owning parent (the menubar app) goes away, or on a signal.
	runErr := comps.WaitForShutdown(ctx)
	// Release the headless lease before draining collectors/sinks so hooks
	// disengage immediately instead of blocking against a shutting-down daemon.
	if headless != nil {
		headless.Release()
	}
	comps.Shutdown()
	if runErr != nil {
		log.Fatalf("daemon stopped: %v", runErr)
	}
}

// reportControlSocket sends one datagram on the app's per-launch socket pair.
// Resolve the bound listener's kernel identity so the app can verify the exact
// process instance on the connection that will carry the stop intent.
func reportControlSocket(path string) error {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	peer, err := api.NewPeerChecker().PeerCred(conn)
	if err != nil {
		return err
	}
	if int(peer.PID) != os.Getpid() {
		return fmt.Errorf("control socket is served by pid %d", peer.PID)
	}
	return json.NewEncoder(os.Stdin).Encode(struct {
		Path       string `json:"path"`
		PID        int32  `json:"pid"`
		UID        int    `json:"uid"`
		PIDVersion uint32 `json:"pidVersion"`
	}{path, peer.PID, peer.UID, peer.PIDVersion})
}
