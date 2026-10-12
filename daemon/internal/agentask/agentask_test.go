package agentask

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memStore struct {
	mu       sync.Mutex
	sessions []model.Session
	asks     map[int64]model.AgentAsk
	ledger   []model.CleanupEntry
	audit    []store.AuditEntry
}

func (m *memStore) SessionsInWorkspace(string) []model.Session { return m.sessions }
func (m *memStore) PutAgentAsk(a model.AgentAsk) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	a.ID = int64(len(m.asks) + 1)
	m.asks[a.ID] = a
	return a.ID
}
func (m *memStore) FinishAgentAsk(a model.AgentAsk) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.asks[a.ID] = a
}
func (m *memStore) PutCleanup(e model.CleanupEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ledger = append(m.ledger, e)
}
func (m *memStore) PutAudit(a store.AuditEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, a)
}

// fakeCLI writes an executable stand-in for claude or codex into bin.
func fakeCLI(t *testing.T, bin, name, script string) {
	t.Helper()
	p := filepath.Join(bin, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T, harness string) (*Asker, *memStore, string, string) {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	wt, bin := filepath.Join(root, "wt"), filepath.Join(root, "bin")
	for _, d := range []string{wt, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	st := &memStore{asks: map[int64]model.AgentAsk{}, sessions: []model.Session{
		{ID: "sess-1234", Harness: harness, Workspace: wt, Status: model.SessionActive, Confidence: model.ConfHook},
	}}
	a := New(st, root)
	a.binDirs = []string{bin}
	return a, st, wt, bin
}

func TestClaudeAskResumesTheSessionAndRecordsThePR(t *testing.T) {
	a, st, wt, bin := setup(t, "claude")
	args := filepath.Join(filepath.Dir(bin), "args.txt")
	fakeCLI(t, bin, "claude", `printf '%s\n' "$@" > "`+args+`"
pwd >> "`+args+`"
printf '%s\n' '{"type":"result","result":"Committed and opened it.\nWORKTREE-VERDICT: pr https://github.com/o/r/pull/9","total_cost_usd":0.21}'
echo 'a warning on stderr' >&2
`)
	ask, err := a.Ask(Request{Path: wt, Repo: "/r", Branch: "feat/x", State: "keep", Reasons: []string{"2 uncommitted changes"}})
	if err != nil || ask.Status != "running" || ask.SessionID != "sess-1234" {
		t.Fatalf("Ask = %+v, %v", ask, err)
	}
	a.Wait()
	got := st.asks[ask.ID]
	if got.Status != "answered" || got.Verdict != "pr" || got.Detail != "https://github.com/o/r/pull/9" || got.CostUSD != 0.21 || got.FinishedAt == nil {
		t.Fatalf("finished ask = %+v", got)
	}
	b, _ := os.ReadFile(args)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	joined := strings.Join(lines, "|")
	for _, want := range []string{"--resume|sess-1234|--fork-session|-p|", "--output-format|json|" + wt} {
		if !strings.Contains(joined, want) {
			t.Fatalf("claude args/cwd %q lack %q", joined, want)
		}
	}
	// Claude counts the resumed session's past spend against a budget flag.
	if strings.Contains(joined, "--max-budget-usd") {
		t.Fatalf("claude args %q carry a budget cap", joined)
	}
	if !strings.Contains(joined, "WORKTREE-VERDICT: removable <reason>") || !strings.Contains(joined, "- 2 uncommitted changes") {
		t.Fatalf("prompt missing the request or the reasons: %q", joined)
	}
	if len(st.ledger) != 1 || st.ledger[0].Action != "ask:pr" || len(st.audit) != 1 || st.audit[0].Action != "worktree-ask" {
		t.Fatalf("ledger %+v audit %+v", st.ledger, st.audit)
	}
}

// A failed ask names the agent's own error: claude's JSON result when it
// reports one, else the end of stderr, with no empty tail.
func TestFailedAskNamesTheAgentsError(t *testing.T) {
	budget := `{"type":"result","subtype":"error_max_budget_usd","is_error":true,"errors":["Reached maximum budget ($1)"],"total_cost_usd":6.48}`
	for _, c := range []struct {
		name, script, detail string
	}{
		{"claude error result", "printf '%s\\n' '" + budget + "'\nexit 1\n", "exit status 1: Reached maximum budget ($1)"},
		{"claude error result, exit 0", "printf '%s\\n' '" + budget + "'\n", "Reached maximum budget ($1)"},
		{"claude error with only a result", "printf '%s\\n' '{\"type\":\"result\",\"is_error\":true,\"result\":\"API Error: 529 overloaded\"}'\nexit 1\n", "exit status 1: API Error: 529 overloaded"},
		{"claude error with only a subtype", "printf '%s\\n' '{\"type\":\"result\",\"subtype\":\"error_max_turns\",\"is_error\":true}'\nexit 1\n", "exit status 1: error_max_turns"},
		{"claude error with only a subtype, exit 0", "printf '%s\\n' '{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true}'\n", "error_during_execution"},
		{"claude errors that are not text", "printf '%s\\n' '{\"type\":\"result\",\"is_error\":true,\"errors\":[{\"message\":\"x\"}]}'\nexit 1\n", "exit status 1: claude reported an error"},
		{"stderr", "echo 'not json'\necho 'boom' >&2\nexit 3\n", "exit status 3: boom"},
		{"nothing said", "exit 2\n", "exit status 2"},
	} {
		a, st, wt, bin := setup(t, "claude")
		fakeCLI(t, bin, "claude", c.script)
		ask, err := a.Ask(Request{Path: wt, State: "keep"})
		if err != nil {
			t.Fatal(err)
		}
		a.Wait()
		if got := st.asks[ask.ID]; got.Status != "failed" || got.Verdict != "none" || got.Detail != c.detail {
			t.Errorf("%s: ask = %q %q %q, want failed none %q", c.name, got.Status, got.Verdict, got.Detail, c.detail)
		}
	}
	// A verdict is the agent's answer even when the run also reports an error;
	// a reply that is not an error but names no verdict is answered.
	for _, c := range []struct {
		name, script, status, verdict, detail string
	}{
		{"verdict despite an error", `printf '%s\n' '{"type":"result","is_error":true,"result":"done\nWORKTREE-VERDICT: keep busy"}'` + "\nexit 1\n", "answered", "keep", "busy"},
		{"no verdict", `printf '%s\n' '{"type":"result","is_error":false,"result":"I looked around."}'` + "\n", "answered", "none", "the reply had no WORKTREE-VERDICT line"},
	} {
		a, st, wt, bin := setup(t, "claude")
		fakeCLI(t, bin, "claude", c.script)
		ask, err := a.Ask(Request{Path: wt, State: "keep"})
		if err != nil {
			t.Fatal(err)
		}
		a.Wait()
		if got := st.asks[ask.ID]; got.Status != c.status || got.Verdict != c.verdict || got.Detail != c.detail {
			t.Errorf("%s: ask = %q %q %q, want %q %q %q", c.name, got.Status, got.Verdict, got.Detail, c.status, c.verdict, c.detail)
		}
	}
}

func TestCodexAskReadsTheLastMessageFile(t *testing.T) {
	a, st, wt, bin := setup(t, "codex")
	fakeCLI(t, bin, "codex", `[ "$1 $2 $3" = "exec resume sess-1234" ] || exit 7
while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
printf 'Checked: nothing here.\n  WORKTREE-VERDICT: removable scratch branch, merged upstream\n' > "$out"
echo "progress noise"
`)
	ask, err := a.Ask(Request{Path: wt, State: "review"})
	if err != nil {
		t.Fatal(err)
	}
	a.Wait()
	got := st.asks[ask.ID]
	if got.Verdict != "removable" || got.Detail != "scratch branch, merged upstream" || got.Status != "answered" {
		t.Fatalf("codex ask = %+v", got)
	}
}

func TestAskTimeoutBusyAndNoSession(t *testing.T) {
	a, st, wt, bin := setup(t, "claude")
	fakeCLI(t, bin, "claude", "sleep 5\n")
	a.timeout = 300 * time.Millisecond
	ask, err := a.Ask(Request{Path: wt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Ask(Request{Path: wt}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second ask while running: %v, want ErrBusy", err)
	}
	start := time.Now()
	a.Wait()
	if got := st.asks[ask.ID]; got.Status != "timeout" || got.Verdict != "none" {
		t.Fatalf("timed-out ask = %+v", got)
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("a timed-out ask took %v to stop: its children kept running", waited)
	}

	st.sessions = []model.Session{{ID: "x", Harness: "cursor-ide", Workspace: wt}}
	if _, err := a.Ask(Request{Path: wt}); !errors.Is(err, ErrNoSession) {
		t.Fatalf("no resumable harness: %v, want ErrNoSession", err)
	}
	st.sessions = nil
	if _, err := a.Ask(Request{Path: wt}); !errors.Is(err, ErrNoSession) {
		t.Fatalf("no session: %v", err)
	}
	st.sessions = []model.Session{{ID: "idle", Harness: "codex", Workspace: wt, Status: model.SessionIdle, Confidence: model.ConfHook}}
	if _, err := a.Ask(Request{Path: wt}); !errors.Is(err, ErrNoSession) {
		t.Fatalf("idle session: %v", err)
	}
	st.sessions = []model.Session{{ID: "y", Harness: "codex", Workspace: wt, Status: model.SessionActive, Confidence: model.ConfHook}}
	if _, err := a.Ask(Request{Path: wt}); err == nil || !strings.Contains(err.Error(), "codex CLI is not installed") {
		t.Fatalf("missing CLI: %v", err)
	}
}

func TestParseVerdict(t *testing.T) {
	for in, want := range map[string][2]string{
		"done\nWORKTREE-VERDICT: pr https://x/pull/1":                             {"pr", "https://x/pull/1"},
		"- `WORKTREE-VERDICT: keep` still testing":                                {"keep", "still testing"},
		"WORKTREE-VERDICT: keep a\nlater\n**WORKTREE-VERDICT: removable** merged": {"removable", "merged"},
		"WORKTREE-VERDICT: delete it":                                             {"", ""},
		"no verdict here":                                                         {"", ""},
	} {
		v, d := ParseVerdict(in)
		if v != want[0] || d != want[1] {
			t.Errorf("ParseVerdict(%q) = %q, %q; want %q, %q", in, v, d, want[0], want[1])
		}
	}
}
