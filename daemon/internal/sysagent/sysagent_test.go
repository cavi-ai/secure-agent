package sysagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// fakeOllama serves the three endpoints the agent uses; reply is the chat
// answer, and every chat request body is kept.
type fakeOllama struct {
	*httptest.Server
	mu       sync.Mutex
	reply    string
	requests []map[string]any
}

func newFakeOllama(t *testing.T, version string, models ...string) *fakeOllama {
	f := &fakeOllama{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			var list []map[string]string
			for _, m := range models {
				list = append(list, map[string]string{"name": m})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"models": list})
		case "/api/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
		case "/v1/chat/completions":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.requests = append(f.requests, body)
			reply := f.reply
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": reply}}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func TestAutoChatModelSkipsEmbeddingOnlyModel(t *testing.T) {
	ol := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{
				map[string]any{"name": "embeddinggemma:latest", "capabilities": []string{"embedding"}},
				map[string]any{"name": "qwen3:latest", "capabilities": []string{"completion", "tools"}},
			}})
		case "/api/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "0.15.1"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ol.Close()
	info := probe(context.Background(), ol.Client(), ol.URL)
	got, err := chatModel(config.SystemAgentConfig{}, info)
	if err != nil || got != "qwen3:latest" {
		t.Fatalf("auto-selected %q, %v; want chat-capable model", got, err)
	}
	if _, err := chatModel(config.SystemAgentConfig{Model: "embeddinggemma:latest"}, info); err == nil || !strings.Contains(err.Error(), "does not support chat") {
		t.Fatalf("embedding-only explicit model should be rejected: %v", err)
	}
}

func (f *fakeOllama) setReply(s string) {
	f.mu.Lock()
	f.reply = s
	f.mu.Unlock()
}

// fakeBin writes an executable shell script named name into dir.
func fakeBin(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// testAgent builds an enabled agent on a fresh store, the fake Ollama and
// the binaries in bins (name → path).
func testAgent(t *testing.T, endpoint string, bins map[string]string) (*Agent, *store.Store) {
	t.Helper()
	st, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := New(st, filepath.Join(t.TempDir(), "sysagent"), func(s string) (string, bool) {
		if strings.Contains(s, "ENCODED-SECRET") {
			return s, false
		}
		return strings.ReplaceAll(s, "ghp_TESTTOKEN", "[REDACTED:github-pat]"), true
	})
	a.look = func(name string) string { return bins[name] }
	a.openTerminal = nil
	a.home = t.TempDir()
	a.SetConfig(config.SystemAgentConfig{Enabled: true, Endpoint: endpoint, TimeoutMinutes: 1})
	return a, st
}

func TestSkillsLoadAndSelect(t *testing.T) {
	all := Skills()
	var ids []string
	for _, s := range all {
		ids = append(ids, s.ID)
		if s.Title == "" || s.Summary == "" || len(s.Keywords) == 0 || !strings.Contains(s.Body, "Rules") {
			t.Errorf("skill %s is incomplete: %+v", s.ID, s)
		}
	}
	if want := []string{"ssh", "git", "signing", "claude", "codex", "openclaw", "hermes"}; !slices.Equal(ids, want) {
		t.Fatalf("skills = %v, want %v", ids, want)
	}
	got := selectSkills("Set up signed commits with my new ssh key; ssh-keygen then gpgsign", 3)
	if len(got) < 2 || !slices.ContainsFunc(got, func(s Skill) bool { return s.ID == "signing" }) ||
		!slices.ContainsFunc(got, func(s Skill) bool { return s.ID == "ssh" }) {
		t.Fatalf("selected %v, want signing and ssh", got)
	}
	if got := selectSkills("redesign the landing page", 3); len(got) != 0 {
		t.Fatalf("'design' must not select the signing skill: %v", got)
	}
}

func TestBuildLaunchRecipes(t *testing.T) {
	sp := launchSpec{Endpoint: "http://127.0.0.1:11434", Model: "qwen3-coder", Workdir: "/w", Task: "You are the task",
		StateDir: "/state", Tag: "7-1", TimeoutSec: 600}
	forbidden := []string{"--dangerously-skip-permissions", "bypassPermissions", "--dangerously-bypass-approvals-and-sandbox",
		"danger-full-access", "--yolo", "HERMES_YOLO_MODE=1", `"mode":"full"`}
	for _, h := range Harnesses {
		for _, mode := range []string{ModeHeadless, ModeTerminal} {
			l, err := buildLaunch(h.ID, mode, sp)
			if h.ID == "pi" && mode == ModeHeadless {
				if err == nil {
					t.Fatal("Pi must refuse headless without a sandbox")
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s %s: %v", h.ID, mode, err)
			}
			all := strings.Join(append(append([]string{}, l.Args...), l.Env...), " ")
			for _, f := range l.Files {
				all += " " + string(f)
			}
			for _, bad := range forbidden {
				if strings.Contains(all, bad) {
					t.Errorf("%s %s carries %q: %s", h.ID, mode, bad, all)
				}
			}
			if n := slices.Index(l.Args, sp.Task); n < 0 || slices.Index(l.Args[n+1:], sp.Task) >= 0 {
				t.Errorf("%s %s: the task must be one argument, once: %q", h.ID, mode, l.Args)
			}
			if !strings.Contains(all, "127.0.0.1:11434") {
				t.Errorf("%s %s does not point at the local endpoint: %s", h.ID, mode, all)
			}
			if !slices.Contains(l.Env, "NO_PROXY=127.0.0.1,localhost,::1") {
				t.Errorf("%s %s: loopback must bypass any proxy: %v", h.ID, mode, l.Env)
			}
		}
	}
	l, _ := buildLaunch("claude", ModeHeadless, sp)
	if !slices.Contains(l.Args, "acceptEdits") || !slices.Contains(l.Args, "WebFetch,WebSearch") || !slices.Contains(l.Env, "ANTHROPIC_API_KEY=") {
		t.Errorf("claude headless: %q %q", l.Args, l.Env)
	}
	var settings struct{ Env map[string]string }
	if i := slices.Index(l.Args, "--settings"); i < 0 || json.Unmarshal([]byte(l.Args[i+1]), &settings) != nil ||
		settings.Env["ANTHROPIC_BASE_URL"] != sp.Endpoint {
		t.Errorf("claude --settings must pin the endpoint over user settings: %q", l.Args)
	}
	l, _ = buildLaunch("codex", ModeHeadless, sp)
	if l.Args[0] != "exec" || !slices.Contains(l.Args, "workspace-write") || l.AnswerFile != "/state/codex-answer-7-1.txt" ||
		!slices.Contains(l.Env, "CODEX_OSS_BASE_URL=http://127.0.0.1:11434/v1") {
		t.Errorf("codex headless: %q %q", l.Args, l.Env)
	}
	for mode, want := range map[string]string{ModeHeadless: `"mode": "deny"`, ModeTerminal: `"mode": "ask"`} {
		l, _ = buildLaunch("openclaw", mode, sp)
		cfg := string(l.Files["/state/openclaw-7-1.json"])
		if !strings.Contains(cfg, want) || !strings.Contains(cfg, `"primary": "ollama/qwen3-coder"`) || strings.Contains(cfg, "/v1") {
			t.Errorf("openclaw %s config: %s", mode, cfg)
		}
	}
	l, _ = buildLaunch("hermes", ModeHeadless, sp)
	if !slices.Contains(l.Env, "CUSTOM_BASE_URL=http://127.0.0.1:11434/v1") || !slices.Contains(l.Env, "HERMES_WRITE_SAFE_ROOT=/w") ||
		!slices.Contains(l.Unset, "HERMES_YOLO_MODE") {
		t.Errorf("hermes headless: %q %q %q", l.Args, l.Env, l.Unset)
	}
	l, _ = buildLaunch("pi", ModeTerminal, sp)
	if !l.CleanEnv || !strings.Contains(commandLine("pi", l, sp.Task), "env -i ") ||
		!strings.Contains(terminalScript(1, model.SysAgentRun{Workdir: sp.Workdir}, "pi", l), "env -i ") ||
		!slices.Contains(l.Env, "PI_OFFLINE=1") || !slices.Contains(l.Args, "read,grep,find,ls,edit,write") ||
		!slices.Contains(l.Args, "--no-extensions") || strings.Contains(strings.Join(l.Args, " "), "bash") ||
		!strings.Contains(string(l.Files["/state/pi-7-1/models.json"]), `"baseUrl":"http://127.0.0.1:11434/v1"`) {
		t.Fatalf("Pi must be isolated and pinned to Ollama: %+v", l)
	}
	if _, err := buildLaunch("cursor", ModeHeadless, sp); err == nil {
		t.Error("an unknown harness must be refused")
	}
}

func TestMergeEnvAndShellQuote(t *testing.T) {
	got := mergeEnv([]string{"PATH=/bin", "CLAUDE_CODE_OAUTH_TOKEN=x", "ANTHROPIC_BASE_URL=https://elsewhere", "NO_PROXY=corp.example"},
		[]string{"ANTHROPIC_BASE_URL=http://127.0.0.1:11434", "NO_PROXY=127.0.0.1,localhost,::1"}, []string{"CLAUDE_CODE_OAUTH_TOKEN"})
	want := []string{"PATH=/bin", "ANTHROPIC_BASE_URL=http://127.0.0.1:11434", "NO_PROXY=127.0.0.1,localhost,::1,corp.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("mergeEnv = %q, want %q", got, want)
	}
	if q := shellQuote("it's $(rm -rf ~)"); q != `'it'\''s $(rm -rf ~)'` {
		t.Fatalf("shellQuote = %s", q)
	}
	if q := shellQuote("/usr/local/bin/claude"); q != "/usr/local/bin/claude" {
		t.Fatalf("safe word quoted: %s", q)
	}
}

func TestParseLocalCommand(t *testing.T) {
	user := model.SysAgentMessage{Workdir: "/tmp"}
	text, action := parseLocalCommand("Use Terminal.\n```local-command\n"+
		`{"command":"ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_work","mode":"terminal","workdir":"relative"}`+"\n```", user, "/home")
	if text != "Use Terminal." || action == nil || action.Mode != ModeTerminal || action.Workdir != "/tmp" {
		t.Fatalf("text=%q action=%+v", text, action)
	}
	for _, bad := range []string{"```dispatch\n{\"task\":\"run\"}\n```", "```local-command\n{\"command\":\"\"}\n```",
		"```local-command\n{\"command\":\"echo x\"}\n```\n```local-command\n{\"command\":\"echo y\"}\n```"} {
		if _, got := parseLocalCommand(bad, user, "/home"); got != nil {
			t.Fatalf("invalid or ambiguous command accepted: %q %+v", bad, got)
		}
	}
}

func TestLocalCommandRequiresSeparateOneTimeExecution(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3:latest")
	ol.setReply("I can check locally.\n```local-command\n" +
		`{"command":"printf '%s' \"${OPENAI_API_KEY:-unset}\"","mode":"headless"}` + "\n```")
	a, st := testAgent(t, ol.URL, nil)
	t.Setenv("OPENAI_API_KEY", "SHOULD_NOT_INHERIT")
	work := t.TempDir()
	if _, err := a.Send(ChatInput{Message: "check my local environment", Workdir: work}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	msgs := st.SysAgentMessages(10)
	if len(msgs) != 2 || msgs[1].LocalCommand == nil || len(st.SysAgentRuns(10)) != 0 {
		t.Fatalf("chat executed without confirmation: %+v", msgs)
	}
	run, err := a.RunLocal(msgs[1].ID)
	if err != nil || run.Status != "running" {
		t.Fatalf("run=%+v err=%v", run, err)
	}
	if _, err := a.RunLocal(msgs[1].ID); !errors.Is(err, ErrBusy) {
		t.Fatalf("command ran twice: %v", err)
	}
	a.Wait()
	runs := st.SysAgentRuns(10)
	if len(runs) != 1 || runs[0].Status != "done" || runs[0].Output != "unset" {
		t.Fatalf("local command result or environment: %+v", runs)
	}
}

func TestSendProposesLocalCommandWithoutRoutingToHarness(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3:latest")
	ol.setReply("The key passphrase stays in Terminal.\n```local-command\n" +
		`{"command":"ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_work","mode":"terminal","workdir":"/tmp"}` + "\n```")
	a, st := testAgent(t, ol.URL, map[string]string{})
	m, err := a.Send(ChatInput{Message: "set up commit signing with ghp_TESTTOKEN", Workdir: "/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	a.Wait()
	if m.Content != "set up commit signing with [REDACTED:github-pat]" {
		t.Fatalf("user message stored unmasked: %q", m.Content)
	}
	msgs := st.SysAgentMessages(10)
	if len(msgs) != 2 || msgs[1].Role != "assistant" || msgs[1].LocalCommand == nil {
		t.Fatalf("messages = %+v", msgs)
	}
	reply := msgs[1]
	if reply.Proposal != nil || reply.LocalCommand.Mode != ModeTerminal || reply.LocalCommand.Workdir != "/tmp" || !slices.Contains(reply.Skills, "signing") {
		t.Fatalf("reply = %+v", reply)
	}
	if len(st.SysAgentPlans(10)) != 0 || len(st.SysAgentRuns(10)) != 0 {
		t.Fatal("a chat reply must never run a command or create a harness plan")
	}
	// The model saw the masked text and signing skill, never a harness route.
	var seen strings.Builder
	for _, m := range ol.requests[0]["messages"].([]any) {
		seen.WriteString(m.(map[string]any)["content"].(string) + "\n")
	}
	for _, want := range []string{`[REDACTED:github-pat]`, `<skill id="signing">`, `You do not call other coding agents during chat`} {
		if !strings.Contains(seen.String(), want) {
			t.Errorf("chat request lacks %s", want)
		}
	}
	if strings.Contains(seen.String(), "ghp_TESTTOKEN") || ol.requests[0]["model"] != "qwen3:latest" || ol.requests[0]["think"] != false {
		t.Errorf("chat request = %v", ol.requests[0])
	}
	if _, err := a.Send(ChatInput{Message: "route me", Harness: "codex"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("chat must reject an ambiguous harness selector: %v", err)
	}
}

func TestSendRefusesAndNotes(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3")
	a, st := testAgent(t, ol.URL, nil)
	if _, err := a.Send(ChatInput{Message: "token ENCODED-SECRET"}); !errors.Is(err, ErrSecret) {
		t.Fatalf("unmaskable secret: err = %v", err)
	}
	if _, err := a.Send(ChatInput{Message: "  "}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty: err = %v", err)
	}
	if n := len(st.SysAgentMessages(10)); n != 0 {
		t.Fatalf("refused messages were stored: %d", n)
	}
	// A down model leaves the message and a note saying it is kept.
	ol.Close()
	if _, err := a.Send(ChatInput{Message: "rotate my codex login"}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	msgs := st.SysAgentMessages(10)
	if len(msgs) != 2 || msgs[1].Role != "note" || !strings.Contains(msgs[1].Content, "Harness handoff") {
		t.Fatalf("messages = %+v", msgs)
	}
	a.SetConfig(config.SystemAgentConfig{Enabled: true, Endpoint: "http://10.1.2.3:11434"})
	if _, err := a.Send(ChatInput{Message: "hi"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("a non-loopback endpoint must read as off: %v", err)
	}
	if s := a.Status(context.Background()); s.Enabled || s.Reachable {
		t.Fatalf("status = %+v", s)
	}
}

func TestDispatchHeadlessRunsTheHarness(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3-coder:latest")
	bins := t.TempDir()
	record := filepath.Join(bins, "record")
	codex := fakeBin(t, bins, "codex", `printf '%s\n' "$@" > `+record+`
env | grep -E '^(CODEX_OSS_BASE_URL|NO_PROXY)=' >> `+record+`
pwd >> `+record+`
while [ $# -gt 1 ]; do [ "$1" = "-o" ] && printf 'Configured signing. ghp_TESTTOKEN\n' > "$2"; shift; done
echo progress
`)
	a, st := testAgent(t, ol.URL, map[string]string{"codex": codex})
	work := t.TempDir()
	p, err := a.SavePlan(PlanInput{Title: "Sign", Harness: "codex", Mode: ModeHeadless, Workdir: work, Task: "Configure signing", Skills: []string{"signing", "bogus"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Skills, []string{"signing"}) || p.Source != "operator" {
		t.Fatalf("plan = %+v", p)
	}
	run, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID, Model: "qwen3-coder"})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "running" || !strings.Contains(run.Command, "CODEX_OSS_BASE_URL=") || !strings.Contains(run.Command, "<task>") {
		t.Fatalf("run = %+v", run)
	}
	if _, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second dispatch while running: %v", err)
	}
	a.Wait()
	runs := st.SysAgentRuns(5)
	if len(runs) != 1 || runs[0].Status != "done" || runs[0].Output != "Configured signing. [REDACTED:github-pat]" || runs[0].FinishedAt == nil {
		t.Fatalf("runs = %+v", runs)
	}
	if p, _ = st.GetSysAgentPlan(p.ID); p.Status != "done" || p.RunID != run.ID || p.Model != "qwen3-coder" {
		t.Fatalf("plan after run = %+v", p)
	}
	got, _ := os.ReadFile(record)
	for _, want := range []string{"exec\n--oss\n--local-provider\nollama\n-m\nqwen3-coder\n--sandbox\nworkspace-write",
		"CODEX_OSS_BASE_URL=" + ol.URL + "/v1", "<skill id=\"signing\">", "Task: Sign\nConfigure signing", "NO_PROXY=127.0.0.1,localhost,::1", work} {
		if !strings.Contains(string(got), want) {
			t.Errorf("harness saw no %q in:\n%s", want, got)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(a.stateDir, "codex-answer-*")); len(left) != 0 {
		t.Errorf("answer file left behind: %v", left)
	}
}

func TestDispatchTerminalOpensOrHandsOver(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3-coder:latest")
	a, st := testAgent(t, ol.URL, map[string]string{"openclaw": "/opt/bin/openclaw"})
	p, err := a.SavePlan(PlanInput{Harness: "openclaw", Mode: ModeTerminal, Workdir: t.TempDir(), Task: "Log in to the provider"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "manual" || !strings.HasPrefix(run.Detail, "Run it in a terminal: sh ") {
		t.Fatalf("no terminal: run = %+v", run)
	}
	var opened string
	a.openTerminal = func(script string) error { opened = script; return nil }
	run, err = a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID})
	if err != nil || run.Status != "opened" {
		t.Fatalf("run = %+v, %v", run, err)
	}
	script, err := os.ReadFile(opened)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(opened)
	s := string(script)
	for _, want := range []string{"rm -f -- \"$0\"", "cd -- " + shellQuote(p.Workdir), "export OPENCLAW_CONFIG_PATH=",
		"export NO_PROXY=127.0.0.1,localhost,::1\"${NO_PROXY:+,$NO_PROXY}\"", "/opt/bin/openclaw chat --message 'You are running on a local model",
		"rm -f -- " + a.stateDir + "/openclaw-"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("script mode = %v", fi.Mode().Perm())
	}
	if p, _ = st.GetSysAgentPlan(p.ID); p.Status != "opened" {
		t.Fatalf("plan = %+v", p)
	}
}

func TestDispatchUnavailableKeepsThePlan(t *testing.T) {
	ol := newFakeOllama(t, "0.12.0", "qwen3")
	a, st := testAgent(t, ol.URL, map[string]string{"claude": "/opt/bin/claude"})
	p, err := a.SavePlan(PlanInput{Harness: "claude", Mode: ModeHeadless, Workdir: t.TempDir(), Task: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID}); !errors.Is(err, ErrUnavailable) ||
		!strings.Contains(err.Error(), "needs Ollama 0.14.0") {
		t.Fatalf("old Ollama: err = %v", err)
	}
	plans := a.Plans(context.Background(), 10)
	if len(plans) != 1 || plans[0].Ready || plans[0].Status != "saved" || !strings.Contains(plans[0].Note, "0.14.0") {
		t.Fatalf("plans = %+v", plans)
	}
	if _, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID, Workdir: "/does/not/exist"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing folder: %v", err)
	}
	if _, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID, Workdir: "/"}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "narrower than /") {
		t.Fatalf("headless in /: %v", err)
	}
	if _, err := a.SavePlan(PlanInput{Harness: "claude", Mode: ModeHeadless, Workdir: "rel", Task: "t"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative folder: %v", err)
	}
	if _, err := a.SavePlan(PlanInput{Harness: "claude", Mode: ModeHeadless, Workdir: "/tmp", Task: "ENCODED-SECRET"}); !errors.Is(err, ErrSecret) {
		t.Fatalf("secret task: %v", err)
	}
	if err := a.DeletePlan(p.ID); err != nil || len(st.SysAgentPlans(10)) != 0 {
		t.Fatalf("delete: %v", err)
	}
}

func TestStatusReportsHarnessReadiness(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "llama3.2:latest", "qwen3-coder:latest")
	a, _ := testAgent(t, ol.URL, map[string]string{"claude": "/opt/bin/claude", "hermes": "/opt/bin/hermes"})
	a.SetConfig(config.SystemAgentConfig{Enabled: true, Endpoint: ol.URL + "/", HarnessModel: "qwen3-coder"})
	s := a.Status(context.Background())
	if !s.Enabled || !s.Reachable || s.OllamaVersion != "0.15.1" || s.Model != "llama3.2:latest" || s.HarnessModel != "qwen3-coder" || len(s.Skills) != 7 {
		t.Fatalf("status = %+v", s)
	}
	ready := map[string]bool{}
	for _, h := range s.Harnesses {
		ready[h.ID] = h.Ready
	}
	if !ready["claude"] || ready["codex"] || ready["openclaw"] || !ready["hermes"] {
		t.Fatalf("readiness = %v", ready)
	}
	a.SetConfig(config.SystemAgentConfig{Enabled: true, Endpoint: ol.URL, HarnessModel: "missing"})
	for _, h := range a.Status(context.Background()).Harnesses {
		if h.ID == "claude" && (h.Ready || !strings.Contains(h.Reason, "ollama pull missing")) {
			t.Fatalf("a model that is not pulled: %+v", h)
		}
	}
}

func TestComposeTask(t *testing.T) {
	got := composeTask(model.SysAgentPlan{Workdir: "/w", Title: "T", Task: "Do it", Steps: []string{"one"}, Skills: []string{"ssh"}})
	if strings.HasPrefix(got, "-") || !strings.Contains(got, "Work in /w.") || !strings.Contains(got, "1. one") ||
		!strings.Contains(got, "<skill id=\"ssh\">") || !strings.Contains(got, "Never print, copy or send secret values") {
		t.Fatalf("task = %s", got)
	}
}

// A daemon that stopped mid-run leaves a "running" plan and run; the next
// start closes both and the plan can be dispatched and deleted again.
func TestRecoverClosesRunsAStoppedDaemonLeft(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3")
	a, st := testAgent(t, ol.URL, nil)
	p, err := a.SavePlan(PlanInput{Harness: "codex", Mode: ModeHeadless, Workdir: t.TempDir(), Task: "t"})
	if err != nil {
		t.Fatal(err)
	}
	runID := st.PutSysAgentRun(model.SysAgentRun{PlanID: p.ID, Harness: "codex", Status: "running"})
	p.Status, p.RunID = "running", runID
	st.PutSysAgentPlan(p)
	if err := a.DeletePlan(p.ID); err != nil {
		t.Fatalf("a run that is not in flight here must not block the plan: %v", err)
	}
	p.ID = st.PutSysAgentPlan(model.SysAgentPlan{Harness: "codex", Mode: ModeHeadless, Workdir: "/tmp", Task: "t", Status: "running", RunID: runID})
	a.Recover()
	if runs := st.SysAgentRuns(5); runs[0].Status != "failed" || runs[0].FinishedAt == nil || !strings.Contains(runs[0].Detail, "daemon stopped") {
		t.Fatalf("runs = %+v", runs)
	}
	if got, _ := st.GetSysAgentPlan(p.ID); got.Status != "failed" {
		t.Fatalf("plan = %+v", got)
	}
}
