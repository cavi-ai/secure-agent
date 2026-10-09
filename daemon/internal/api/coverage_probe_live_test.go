package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// The shipped installed hook, real Unix peer gate and real SQLite API must
// agree on the same inert challenge. No mock claims end-to-end acceptance.
func TestCoverageProbeInstalledHookLive(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for installed-hook acceptance")
	}
	a, dir := coverageProbeFixture(t)
	src, err := filepath.Abs("../../../plugin/hooks")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json"} {
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	a = New(Deps{Store: a.store, Status: a.statusFn, PeerChecker: NewPeerChecker(), UIPID: int32(os.Getpid())})
	sockDir, err := os.MkdirTemp("", "probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "daemon.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.ServeListener(ctx, listener) }()
	t.Cleanup(func() { cancel(); listener.Close(); <-done })
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	post := func(path string, body any, out any) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Post("http://unix"+path, "application/json", strings.NewReader(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: HTTP %d", path, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	var challenge CoverageProbeChallenge
	post("/coverage/probe", map[string]string{"harness": "claude"}, &challenge)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": map[string]string{"file_path": challenge.Path}, "secure_agent_probe": challenge.ID})
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cmdCancel()
	cmd := exec.CommandContext(cmdCtx, python, challenge.HookPath)
	cmd.Env = append(os.Environ(), "SECURE_AGENT_SOCK="+sock, "SECURE_AGENT_HARNESS=claude")
	cmd.Stdin = strings.NewReader(string(payload))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Permission string `json:"permission"`
		ID         string `json:"secure_agent_probe"`
	}
	if err := json.Unmarshal(out, &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Permission != "deny" || answer.ID != challenge.ID {
		t.Fatalf("installed hook did not return daemon challenge receipt: permission=%q, matching receipt=%v", answer.Permission, answer.ID == challenge.ID)
	}
	var receipt CoverageProbeReceipt
	post("/coverage/probe", map[string]any{"id": challenge.ID, "passed": true}, &receipt)
	if receipt.State != "passed" {
		t.Fatalf("round trip: %s", receipt.State)
	}
	if rows := a.store.QueryEvents(store.EventFilter{Limit: 20}); len(rows) != 0 {
		t.Fatal("synthetic probe manufactured session evidence")
	}
	if rows := a.store.ListGuardDecisions("", 20); len(rows) != 0 {
		t.Fatal("synthetic probe manufactured real guard decisions")
	}
	home := filepath.Dir(filepath.Dir(dir))
	for _, path := range []string{filepath.Join(home, ".agents", "logs", "secret-guard.jsonl"), filepath.Join(home, ".local", "state", "secure-agent", "activity.jsonl")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("synthetic probe wrote real hook activity")
		}
	}
}
