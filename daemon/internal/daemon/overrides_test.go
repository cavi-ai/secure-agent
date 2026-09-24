package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// A daemon whose socket lives outside ~/.config/secure-agent writes the hook
// policy file beside that socket and never touches $HOME's copy.
func TestWriteCwdOverridesBesideSocketLeavesHomeUntouched(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sockDir := t.TempDir()

	var cfg config.Config
	cfg.SocketPath = filepath.Join(sockDir, "daemon.sock")
	cfg.DirectoryGuard.CwdOverrides = []config.CwdOverride{
		{CwdPrefix: "/work/api", Rules: map[string]string{"env-files": "deny"}},
	}
	writeCwdOverrides(cfg)

	if _, err := os.Stat(filepath.Join(sockDir, "guard-cwd-overrides.json")); err != nil {
		t.Fatalf("overrides file beside socket: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config")); !os.IsNotExist(err) {
		t.Fatalf("$HOME/.config must stay untouched, stat err = %v", err)
	}
}
