package agents

import "testing"

func TestNodeProgramKeepsOnlyTheEntryPoint(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"script", []string{"node", "./mcp/server.mjs", "--token", "[REDACTED]"}, "/work/mcp/server.mjs"},
		{"openclaw", []string{"node", "/opt/openclaw/dist/index.js", "gateway"}, "/opt/openclaw/dist/index.js"},
		{"flags", []string{"node", "--no-warnings", "--require", "/opt/preload.cjs", "--import=init", "./openclaw.mjs"}, "/work/openclaw.mjs"},
		{"warning and inspector", []string{"node", "--disable-warning=ExperimentalWarning", "--inspect=127.0.0.1:9229", "./openclaw.mjs"}, "/work/openclaw.mjs"},
		{"heap limit", []string{"node", "--max-old-space-size=4096", "/opt/openclaw/dist/index.js", "gateway", "--port", "12345"}, "/opt/openclaw/dist/index.js"},
		{"separator", []string{"node", "--", "./openclaw.mjs"}, "/work/openclaw.mjs"},
		{"title", []string{"openclaw-gateway"}, "openclaw-gateway"},
		{"eval", []string{"node", "--eval", "[REDACTED]", "openclaw"}, ""},
		{"print", []string{"node", "--print=[REDACTED]", "openclaw"}, ""},
		{"stdin", []string{"node", "-", "openclaw"}, ""},
		{"unknown option", []string{"node", "--unknown-option", "openclaw"}, ""},
		{"unknown assignment", []string{"node", "--unknown-option=value", "openclaw"}, ""},
		{"package script", []string{"node", "--run=serve", "--", "openclaw"}, ""},
		{"missing preload", []string{"node", "--require"}, ""},
		{"missing program", []string{"node", "--"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeProgram(tc.argv, "/work"); got != tc.want {
				t.Fatalf("program=%q, want %q", got, tc.want)
			}
		})
	}
}
