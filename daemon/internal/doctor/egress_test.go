package doctor

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

// The egress check names the agents behind its count, with up to two hosts
// each, and leaves out the rows that do not join the headline (infra
// families and known CDN or cloud hosts).
func TestDoctorEgressNamesAgentsAndHosts(t *testing.T) {
	f := Facts{Status: posture.Status{ProxyEnabled: true, UninspectedEgress: 4}, Egress: []EgressRow{
		{Agent: "codex", Host: "api.openai.com"},
		{Agent: "cursor", Host: "api2.cursor.sh"},
		{Agent: "codex", Host: "chatgpt.com"},
		{Agent: "codex", Host: "ab.chatgpt.com"},
		{Agent: "claude-desktop", Host: "claude.ai", AgentKind: config.AgentKindInfra},
		{Agent: "openclaw", Host: "203.0.113.9", Infra: "Cloudflare"},
	}}
	state, detail := checkEgressRouting(f)
	want := "4 endpoints reached outside the proxy: codex 3 (api.openai.com, chatgpt.com, …), cursor 1 (api2.cursor.sh)"
	if state != Fail || detail != want {
		t.Fatalf("egress check = %s %q, want fail %q", state, detail, want)
	}
	// Without rows the count stands alone.
	f.Egress = nil
	if _, detail := checkEgressRouting(f); detail != "4 endpoints reached outside the proxy" {
		t.Fatalf("detail without rows = %q", detail)
	}
}
