package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
	"github.com/cavi-ai/secure-agent/daemon/internal/shellreview"
)

func TestShellReviewHookTransport(t *testing.T) {
	home, err := os.MkdirTemp("", "sr-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	sock := filepath.Join(home, "d.sock")
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Write([]byte(`{"answers":{"risk":{"type":"choice","choice":"routine","confidence":1,"probabilities":{"routine":1,"review":0,"unknown":0}}}}`))
	}))
	defer modelServer.Close()
	defer close(release)
	st := testStore(t)
	defer st.Close()
	records := make(chan shellreview.Result, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc, err := shellreview.New(ctx, shellreview.Config{Enabled: true, Endpoint: modelServer.URL, TimeoutMS: 5000}, func(s string) (string, bool) { return redact.Scrub(s), true }, func(r shellreview.Result) error {
		err := st.PutShellReview(r)
		records <- r
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	a := newTestAPI(Deps{SocketPath: sock, Store: st, Guard: GuardDeps{ShellReviews: svc}, Status: func() Status { return Status{Running: true} }})
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	defer func() { cancel(); <-done }()
	waitForSocket(t, sock)
	hook, err := filepath.Abs("../../../plugin/hooks/secret_guard.py")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"call-1","session_id":"session-1","tool_input":{"command":"security dump-keychain"}}`
	commandCtx, commandCancel := context.WithTimeout(ctx, 2*time.Second)
	defer commandCancel()
	command := exec.CommandContext(commandCtx, "python3", hook)
	command.Env = append(os.Environ(), "HOME="+home, "SECURE_AGENT_SOCK="+sock, "SECURE_AGENT_ACTIVITY_LOG="+filepath.Join(home, "activity.jsonl"), "SECURE_AGENT_SHELL_REVIEW=1")
	command.Stdin = strings.NewReader(payload)
	output, err := command.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			t.Fatalf("hook: %v: %s", err, exit.Stderr)
		}
		t.Fatalf("hook: %v", err)
	}
	var verdict struct{ Permission string }
	if err := json.Unmarshal(output, &verdict); err != nil || verdict.Permission != "deny" {
		t.Fatalf("hard denial changed: %s %v", output, err)
	}
	// The hook returned while the real classifier transport is still waiting.
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("no model call")
	}
	select {
	case <-records:
		t.Fatal("model did not wait for fixture release")
	default:
	}
	release <- struct{}{}
	select {
	case <-records:
	case <-time.After(2 * time.Second):
		t.Fatal("observation not recorded")
	}
	response, err := unixClient(sock).Get("http://unix/guard/shell-reviews")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		EnforcementConfigured bool                 `json:"enforcement_configured"`
		Observations          []shellreview.Result `json:"observations"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || result.EnforcementConfigured || len(result.Observations) != 1 {
		t.Fatalf("response: %+v", result)
	}
	got := result.Observations[0]
	if got.Choice != "routine" || got.GuardVerdict != "deny" || got.CallID != "call-1" {
		t.Fatalf("observation: %+v", got)
	}
	rules, err := st.ListGuardRules(10)
	if err != nil || len(rules) != 0 {
		t.Fatal("classifier wrote permission")
	}
}

func TestShellCheckHookUsesDaemon(t *testing.T) {
	cases := []struct {
		Name, Command, Choice, Mode, Want string
		ModelOffline, StorageOffline      bool
	}{
		{"routine", "printf '%s\\n' café", "routine", "block", "allow", false, false},
		{"review", "git push --force origin main", "review", "block", "deny", false, false},
		{"unknown", "npm test", "unknown", "block", "deny", false, false},
		{"model-offline", "echo hello", "routine", "block", "deny", true, false},
		{"storage-offline", "echo hello", "routine", "block", "deny", false, true},
		{"observe-mismatch", "echo hello", "routine", "observe", "deny", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			home, err := os.MkdirTemp("", "sc-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(home)
			modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.ModelOffline {
					w.WriteHeader(503)
					return
				}
				probabilities := map[string]float64{"routine": 0, "review": 0, "unknown": 0}
				probabilities[tc.Choice] = 1
				json.NewEncoder(w).Encode(map[string]any{"answers": map[string]any{"risk": map[string]any{"type": "choice", "choice": tc.Choice, "confidence": 1, "probabilities": probabilities}}})
			}))
			defer modelServer.Close()
			st := testStore(t)
			defer st.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			svc, err := shellreview.New(ctx, shellreview.Config{Enabled: true, Mode: tc.Mode, Endpoint: modelServer.URL}, func(v string) (string, bool) { return redact.Scrub(v), true }, func(r shellreview.Result) error {
				if tc.StorageOffline {
					return io.ErrClosedPipe
				}
				return st.PutShellReview(r)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer svc.Close()
			sock := filepath.Join(home, "d.sock")
			a := newTestAPI(Deps{SocketPath: sock, Store: st, Guard: GuardDeps{ShellReviews: svc}})
			done := make(chan error, 1)
			go func() { done <- a.Serve(ctx) }()
			defer func() { cancel(); <-done }()
			waitForSocket(t, sock)
			hook, err := filepath.Abs("../../../plugin/hooks/secret_guard.py")
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]string{"command": tc.Command}, "cwd": home})
			commandCtx, commandCancel := context.WithTimeout(ctx, 8*time.Second)
			defer commandCancel()
			command := exec.CommandContext(commandCtx, "python3", hook)
			for _, item := range os.Environ() {
				if !strings.HasPrefix(item, "SECURE_AGENT_") && !strings.HasPrefix(item, "HOME=") {
					command.Env = append(command.Env, item)
				}
			}
			command.Env = append(command.Env, "HOME="+home, "SECURE_AGENT_SOCK="+sock, "SECURE_AGENT_ACTIVITY_LOG="+filepath.Join(home, "activity.jsonl"), "SECURE_AGENT_SHELL_REVIEW=block")
			command.Stdin = strings.NewReader(string(payload))
			output, err := command.Output()
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					t.Fatalf("hook: %v: %s", err, exit.Stderr)
				}
				t.Fatal(err)
			}
			var verdict struct{ Permission string }
			if err := json.Unmarshal(output, &verdict); err != nil || verdict.Permission != tc.Want {
				t.Fatalf("verdict=%s want=%s error=%v", output, tc.Want, err)
			}
			if !tc.StorageOffline && tc.Mode == "block" {
				records, err := st.RecentShellReviews(10)
				if err != nil || len(records) != 1 || records[0].Mode != "block" || records[0].ProposedVerdict != tc.Want {
					t.Fatalf("receipts=%+v error=%v", records, err)
				}
			}
		})
	}
}

func TestShellReviewAdmission(t *testing.T) {
	st := testStore(t)
	defer st.Close()
	a := newTestAPI(Deps{Store: st})
	response := httptest.NewRecorder()
	a.buildMux().ServeHTTP(response, httptest.NewRequest("POST", "/guard/shell-review", strings.NewReader("{}")))
	if response.Code != 503 {
		t.Fatalf("disabled status=%d", response.Code)
	}
	if apiroutes.ConsoleAllowed("POST", "/guard/shell-review") {
		t.Fatal("browser can submit hook observations")
	}
	if !apiroutes.IsDecide("POST", "/guard/shell-review") {
		t.Fatal("observation submission bypasses hook peer policy")
	}
	if !apiroutes.IsDecide("POST", "/guard/shell-check") || apiroutes.ConsoleAllowed("POST", "/guard/shell-check") {
		t.Fatal("shell check has incorrect peer admission")
	}
	if !apiroutes.IsNoAgent("/guard/shell-reviews") {
		t.Fatal("agent can read observations")
	}
}
