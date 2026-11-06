package api

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// The egress check names the agents behind its count, with up to two hosts
// each, and leaves out the rows that do not join the headline (infra
// families and known CDN or cloud hosts).
func TestDoctorEgressNamesAgentsAndHosts(t *testing.T) {
	f := doctorFacts{st: Status{ProxyEnabled: true, UninspectedEgress: 4}, egress: []UninspectedEndpoint{
		{Agent: "codex", Host: "api.openai.com", Count: 9},
		{Agent: "cursor", Host: "api2.cursor.sh", Count: 7},
		{Agent: "codex", Host: "chatgpt.com", Count: 5},
		{Agent: "codex", Host: "ab.chatgpt.com", Count: 2},
		{Agent: "claude-desktop", Host: "claude.ai", Count: 4, AgentKind: config.AgentKindInfra},
		{Agent: "openclaw", Host: "203.0.113.9", Count: 3, Infra: "Cloudflare"},
	}}
	state, detail := checkEgressRouting(f)
	want := "4 endpoints reached outside the proxy: codex 3 (api.openai.com, chatgpt.com, …), cursor 1 (api2.cursor.sh)"
	if state != doctorFail || detail != want {
		t.Fatalf("egress check = %s %q, want fail %q", state, detail, want)
	}
	// Without rows the count stands alone.
	f.egress = nil
	if _, detail := checkEgressRouting(f); detail != "4 endpoints reached outside the proxy" {
		t.Fatalf("detail without rows = %q", detail)
	}
}
