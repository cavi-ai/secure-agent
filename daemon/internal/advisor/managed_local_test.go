package advisor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in proof against the owned engine and an already-cached real model.
// No server installation, model download or existing service is touched.
func TestManagedPrivateLocalModel(t *testing.T) {
	model := os.Getenv("SECURE_AGENT_TEST_MANAGED_MODEL")
	bin := os.Getenv("SECURE_AGENT_TEST_MLX_AGENT_BIN")
	if model == "" || bin == "" {
		t.Skip("requires an explicitly selected local model and mlx-agent executable")
	}
	m, err := NewManagedTransport(ManagedSpec{Model: model, Bin: bin})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"Say hello."}],"max_tokens":8,"temperature":0,"stream":true}`, model)
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1/v1/chat/completions", strings.NewReader(payload))
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("private inference status %d", resp.StatusCode)
	}
	if state := m.ProtectionStatus(); state.Transport != privateProtocol || state.State != "running" {
		t.Fatalf("private model status: %+v", state)
	}
	directory := m.process.directory
	pid := m.cmd.Process.Pid
	output, err := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-p", fmt.Sprint(pid), "-iTCP", "-sTCP:LISTEN", "-Fn").CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || len(output) != 0 {
		t.Fatalf("worker TCP listener check: %v %s", err, output)
	}
	conn, err := net.Dial("unix", filepath.Join(directory, "model.sock"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(conn, "GET /_mlx/private HTTP/1.0\r\nHost: attacker.invalid\r\n\r\n")
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	refused, err := io.ReadAll(io.LimitReader(conn, 4096))
	conn.Close()
	if err != nil || !strings.Contains(string(refused), "403") {
		t.Fatalf("foreign Host accepted: %v", err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || !strings.Contains(string(body), "data: [DONE]") || !strings.Contains(string(body), "\"content\"") {
		t.Fatalf("real streaming inference incomplete: %v", err)
	}
	resp.Body.Close()
	m.Close()
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("private runtime directory retained: %v", err)
	}
	t.Log("cached-model streaming, foreign-Host refusal, no worker TCP listener, and cleanup passed")
}
