package daemon

import (
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// The gate reads the taint records beside this daemon's socket, where the
// hook writes them, and never refuses the model API hosts or loopback.
func TestEgressGateReadsHookRecordsAndExemptsModelHosts(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "daemon.sock")
	g := egressGate(config.Config{SocketPath: sock, ProxyInspectHosts: []string{" API.Anthropic.com ", ""}}, nil)
	if g.Dir != filepath.Join(filepath.Dir(sock), "taint") {
		t.Fatalf("taint dir = %q", g.Dir)
	}
	for _, h := range []string{"api.anthropic.com", "localhost", "127.0.0.1", "::1"} {
		if !g.Exempt[h] {
			t.Errorf("%s not exempt", h)
		}
	}
	if len(g.Exempt) != 4 {
		t.Fatalf("exempt = %v", g.Exempt)
	}
}
