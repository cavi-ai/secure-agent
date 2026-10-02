package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/agentenv"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/proxy"
)

// Claude Code's routing comes from the live proxy: its own environment in
// inspect mode with the CA, and the tunnel-mode snippet for its Bash
// commands. Not ready while the proxy is off or the snippet is missing.
func TestClaudeRouting(t *testing.T) {
	if info := claudeRouting(nil, "/c/ca.crt")(); info.Ready || !strings.Contains(info.Reason, "proxy_enabled") {
		t.Fatalf("proxy off: %+v, want not ready naming proxy_enabled", info)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	tok := proxy.LoadToken(filepath.Join(dir, "proxy-token"))
	ps := proxy.NewProxyServer(8443, bus.New(1), nil, nil)
	if info := claudeRouting(ps, ca)(); info.Ready || !strings.Contains(info.Reason, "snippet") {
		t.Fatalf("no snippet: %+v, want not ready naming the snippet", info)
	}
	if _, err := agentenv.WriteSnippet(dir, 8443, tok); err != nil {
		t.Fatal(err)
	}
	info := claudeRouting(ps, ca)()
	if !info.Ready || info.BashEnvPath != filepath.Join(dir, agentenv.SnippetName) {
		t.Fatalf("ready: %+v", info)
	}
	if info.Env["HTTPS_PROXY"] != agentenv.ProxyURL(8443, tok, agentenv.InspectUser) || info.Env["NODE_EXTRA_CA_CERTS"] != ca {
		t.Fatalf("env = %v, want the inspect-mode proxy URL and the CA", info.Env)
	}
}
