package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

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
