package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestBuildRecordsStoreInitializationFailure(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DBPath:     filepath.Join(dir, "events.db"),
		SocketPath: filepath.Join(dir, "daemon.sock"),
	}
	cfg.Firewall.Registry.SaltRef = filepath.Join(dir, "salt")
	if err := os.WriteFile(cfg.DBPath, []byte("invalid SQLite database"), 0o600); err != nil {
		t.Fatal(err)
	}

	path := RunRecordPath(cfg)
	prior, err := StartRun(path, 100, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prior.Stop(RunEndingSignal); err != nil {
		t.Fatal(err)
	}

	c, err := Build(context.Background(), cfg, Options{})
	if c != nil {
		c.Shutdown()
	}
	if err == nil || !strings.Contains(err.Error(), "initialize database schema") || c != nil {
		t.Fatalf("Build returned components=%t, error=%v, want a store initialization failure", c != nil, err)
	}
	prev, found, err := ReadPreviousRun(path)
	if err != nil || !found || prev.Ending != RunEndingStartFailure || prev.Record.PID != os.Getpid() {
		t.Fatalf("read back: %+v found=%v err=%v, want this attempt's start-failure", prev, found, err)
	}

	if err := os.Remove(cfg.DBPath); err != nil {
		t.Fatal(err)
	}
	// The store can now open. Stop the build at the socket bind, after
	// processing findings and before starting collectors.
	blocker := filepath.Join(dir, "socket-parent")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.SocketPath = filepath.Join(blocker, "daemon.sock")
	c, err = Build(context.Background(), cfg, Options{})
	if c != nil {
		c.Shutdown()
	}
	if err == nil || !strings.Contains(err.Error(), "bind control API") || c != nil {
		t.Fatalf("Build returned components=%t, error=%v, want a socket bind failure", c != nil, err)
	}
	st, err := store.Open(cfg.DBPath, cfg.JSONLPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	flags := monitorStoppedFlags(t, st)
	if len(flags) != 2 {
		t.Fatalf("findings = %+v, want the original signal and the failed start", flags)
	}
	reasons := map[string]string{}
	for _, flag := range flags {
		for _, evidence := range flag.Evidence {
			reasons[evidence.Label] = evidence.Text
		}
	}
	if !strings.Contains(reasons["signal"], "pid 100") || !strings.Contains(reasons["start-failure"], "failed during start") {
		t.Fatalf("finding reasons = %+v, want the original signal and the failed start", reasons)
	}
}

func TestBuildRefusesUnavailableControlSocket(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg, err := config.Load(filepath.Join(home, "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Agents = nil
	blocker := filepath.Join(home, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.SocketPath = filepath.Join(blocker, "daemon.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, buildErr := Build(ctx, cfg, Options{})
	if c != nil {
		c.Shutdown()
	}
	if buildErr == nil || c != nil {
		t.Fatalf("Build returned components=%t, error=%v; unavailable API must fail startup", c != nil, buildErr)
	}
	// A failed build must release the SQLite store so the next attempt can open it.
	s, err := store.Open(cfg.DBPath, cfg.JSONLPath)
	if err != nil {
		t.Fatalf("store unavailable after failed startup: %v", err)
	}
	s.Close()
}

func TestAPIFailureTriggersDaemonShutdown(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg, err := config.Load(filepath.Join(home, "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Agents = nil
	// Keep the socket below macOS's Unix-address length limit.
	socketDir, err := os.MkdirTemp("", "sa-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	cfg.SocketPath = filepath.Join(socketDir, "daemon.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Build(ctx, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()
	// An unexpected control listener failure must reach the process owner,
	// rather than leaving a living daemon with no working control endpoint.
	if err := c.apiListener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitForShutdown(ctx); err == nil || ctx.Err() != nil {
		t.Fatalf("API failure did not trigger shutdown: %v, context=%v", err, ctx.Err())
	}
}
