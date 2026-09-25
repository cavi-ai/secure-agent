package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

const claudeLauncher = "Claude.app › claude-code 2.1.281"

func claudeReadFlag(id string, pid int32, session string, ts time.Time) model.Flag {
	return model.Flag{ID: id, Rule: "sensitive-read-then-connect", Severity: 3, TS: ts, PID: pid, Agent: "claude", SessionID: session,
		Process:  &model.FlagProcess{Exe: "/x/claude", Name: "claude", PPID: 1, Launcher: claudeLauncher},
		Evidence: []model.EvidenceItem{{Kind: "read", Label: "/Users/dev/.netrc", Rule: "glob:~/.netrc"}, {Kind: "connect", Label: "evil.example.com:443"}}}
}

func agentGroup(t *testing.T, groups []AttentionGroup, key string) AttentionGroup {
	t.Helper()
	for _, g := range groups {
		if g.Key == key {
			return g
		}
	}
	t.Fatalf("no group %q in %+v", key, groups)
	return AttentionGroup{}
}

// Three exited claude processes in three sessions, none live: the
// agent-level group names them instead of the generic sentence.
func TestAttentionAgentGroupSummaryNamesExitedProcesses(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "cursor", "/w")})
	now := time.Now()
	for i := 0; i < 3; i++ {
		a.store.PutFlag(claudeReadFlag(fmt.Sprintf("c%d", i), int32(700+i), fmt.Sprintf("s%d", i), now.Add(-time.Duration(i+1)*time.Second)))
	}
	g := agentGroup(t, a.computePosture().Groups, "agent:claude")
	if want := "3 processes (claude-code 2.1.281 via Claude.app) across 3 sessions, all exited"; g.Summary != want {
		t.Fatalf("summary = %q, want %q", g.Summary, want)
	}
}

func TestAttentionAgentGroupSummarySingleFlagAndLive(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "cursor", "/w"), mkResourceSession(2, "cursor", "/v")})
	a.store.PutFlag(claudeReadFlag("one", 701, "s1", time.Now()))
	g := agentGroup(t, a.computePosture().Groups, "agent:claude")
	if want := "1 process (claude-code 2.1.281 via Claude.app) in 1 session, exited"; g.Summary != want {
		t.Fatalf("summary = %q, want %q", g.Summary, want)
	}
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

// The snapshot is served on /flags, /flags/{id}/explain and aggregated on
// /patterns — for pids that no longer exist.
func TestFlagProcessServedOnFlagsExplainAndPatterns(t *testing.T) {
	a := explainTestAPI(t)
	now := time.Now()
	for i := 0; i < 3; i++ {
		a.store.PutFlag(claudeReadFlag(fmt.Sprintf("c%d", i), int32(700+i%2), "s1", now.Add(-time.Duration(i+1)*time.Second)))
	}
	zsh := claudeReadFlag("z", 900, "s1", now)
	zsh.Process = &model.FlagProcess{Name: "zsh", Launcher: claudeLauncher}
	a.store.PutFlag(zsh)

	rr := httptest.NewRecorder()
	a.handleFlags(rr, httptest.NewRequest(http.MethodGet, "/flags?limit=10", nil))
	var flags []model.Flag
	if err := json.Unmarshal(rr.Body.Bytes(), &flags); err != nil {
		t.Fatalf("/flags: %v: %s", err, rr.Body.String())
	}
	if len(flags) != 4 || flags[0].Process == nil || flags[0].Process.Launcher != claudeLauncher {
		t.Fatalf("/flags = %+v", flags)
	}

	rr = httptest.NewRecorder()
	a.handleFlagExplain(rr, httptest.NewRequest(http.MethodGet, "/flags/c0/explain", nil))
	var one model.Flag
	if err := json.Unmarshal(rr.Body.Bytes(), &one); err != nil || one.Process == nil || one.Process.Name != "claude" {
		t.Fatalf("/flags/c0/explain = %s (%v)", rr.Body.String(), err)
	}

	p := onlyPattern(t, a.computePatterns(now.Add(-time.Hour), 3))
	want := []model.PatternProcess{{Name: "claude", Launcher: claudeLauncher, Count: 2}, {Name: "zsh", Launcher: claudeLauncher, Count: 1}}
	if len(p.Processes) != 2 || p.Processes[0] != want[0] || p.Processes[1] != want[1] {
		t.Fatalf("pattern processes = %+v, want %+v", p.Processes, want)
	}
}
