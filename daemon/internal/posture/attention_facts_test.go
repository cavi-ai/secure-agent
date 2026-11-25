package posture

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const claudeLauncher = "Claude.app › claude-code 2.1.281"

func claudeReadFlag(id string, pid int32, session string, ts time.Time) model.Flag {
	return model.Flag{ID: id, Rule: "sensitive-read-then-connect", Severity: 3, TS: ts, PID: pid, Agent: "claude", SessionID: session,
		Process:  &model.FlagProcess{Exe: "/x/claude", Name: "claude", PPID: 1, Launcher: claudeLauncher},
		Evidence: []model.EvidenceItem{{Kind: "read", Label: "/Users/dev/.netrc", Rule: "glob:~/.netrc"}, {Kind: "connect", Label: "evil.example.com:443"}}}
}

func TestAttentionAgentGroupSummarySingleFlagAndLive(t *testing.T) {
	live := newAgentGroupFacts()
	live.addFlag(claudeReadFlag("x", 42, "", time.Now()))
	if got := live.summary(map[int32]bool{42: true}); got != "1 process (claude-code 2.1.281 via Claude.app), no session, 1 still running" {
		t.Fatalf("live summary = %q", got)
	}
}

func TestProcessLabel(t *testing.T) {
	for _, c := range []struct{ name, launcher, want string }{
		{"claude", claudeLauncher, "claude-code 2.1.281 via Claude.app"},
		{"zsh", claudeLauncher, "zsh in claude-code 2.1.281 via Claude.app"},
		{"Cursor Helper (Plugin)", "Cursor.app", "Cursor Helper (Plugin) via Cursor.app"},
		{"opencode", "opencode", "opencode"},
		{"node", "", "node"},
	} {
		if got := processLabel(c.name, c.launcher); got != c.want {
			t.Fatalf("processLabel(%q, %q) = %q, want %q", c.name, c.launcher, got, c.want)
		}
	}
}
