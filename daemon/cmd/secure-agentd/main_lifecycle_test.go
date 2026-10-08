package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Run the actual CLI entry point in a child so fatal startup errors and
// signal-driven shutdown are tested without terminating the test runner.
func TestDaemonProcessHelper(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_MAIN") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("secure-agentd", flag.ExitOnError)
	os.Args = []string{"secure-agentd", "--config", os.Getenv("SECURE_AGENT_TEST_CONFIG")}
	main()
	os.Exit(0)
}

func lifecycleFixture(t *testing.T) (string, map[string]any) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sa-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir, map[string]any{
		"net_sample_interval_ms": 1000, "agents": []any{}, "proxy_enabled": false,
		"socket_path":     filepath.Join(dir, "daemon.sock"),
		"db_path":         filepath.Join(dir, "events.db"),
		"jsonl_path":      filepath.Join(dir, "events.jsonl"),
		"sensitive_globs": []any{}, "sensitive_paths": []any{},
		"hermes_home": filepath.Join(dir, "hermes"), "openclaw_home": filepath.Join(dir, "openclaw"),
	}
}

func writeLifecycleConfig(t *testing.T, dir string, cfg map[string]any) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func daemonCommand(ctx context.Context, dir, configPath string) *exec.Cmd {
	var cmd *exec.Cmd
	if binary := os.Getenv("SECURE_AGENT_LIFECYCLE_BINARY"); binary != "" {
		cmd = exec.CommandContext(ctx, binary, "--config", configPath)
	} else {
		cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDaemonProcessHelper$")
	}
	cmd.Env = append(os.Environ(), "HOME="+dir, "SECURE_AGENT_TEST_MAIN=1", "SECURE_AGENT_TEST_CONFIG="+configPath)
	return cmd
}

func TestDaemonStartupFailuresExitNonzero(t *testing.T) {
	for _, failure := range []string{"config", "sqlite", "socket"} {
		t.Run(failure, func(t *testing.T) {
			dir, cfg := lifecycleFixture(t)
			wantError := "failed to load config"
			switch failure {
			case "config":
				cfg["net_sample_interval_ms"] = -1
			case "sqlite":
				cfg["db_path"] = dir
				wantError = "failed to open store"
			case "socket":
				blocker := filepath.Join(dir, "blocker")
				if err := os.WriteFile(blocker, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg["socket_path"] = filepath.Join(blocker, "daemon.sock")
				wantError = "failed to bind control API"
			}
			path := writeLifecycleConfig(t, dir, cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			output, err := daemonCommand(ctx, dir, path).CombinedOutput()
			if ctx.Err() != nil || err == nil || !strings.Contains(string(output), wantError) {
				t.Fatalf("startup failure=%s, exit=%v, context=%v, output=%s", failure, err, ctx.Err(), output)
			}
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
				t.Fatalf("startup refusal must exit 1, got %v", err)
			}
			if strings.Contains(string(output), "panic:") || strings.Contains(string(output), "running on unix socket") {
				t.Fatalf("startup failure announced success or panicked: %s", output)
			}
		})
	}
}

func TestDaemonRecoversAfterConfigRepairAndStopsOnSignal(t *testing.T) {
	dir, cfg := lifecycleFixture(t)
	cfg["net_sample_interval_ms"] = -1
	path := writeLifecycleConfig(t, dir, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if output, err := daemonCommand(ctx, dir, path).CombinedOutput(); err == nil {
		t.Fatalf("invalid config unexpectedly started: %s", output)
	}
	cfg["net_sample_interval_ms"] = 1000
	writeLifecycleConfig(t, dir, cfg)
	cmd := daemonCommand(ctx, dir, path)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	ready := make(chan struct{}, 1)
	var logs bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			logs.WriteString(line + "\n")
			if strings.Contains(line, "running on unix socket") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
		finished <- cmd.Wait()
	}()
	defer func() { cmd.Process.Kill() }()
	select {
	case <-ready:
	case err := <-finished:
		t.Fatalf("repaired config failed startup: %v, %s", err, logs.String())
	case <-ctx.Done():
		t.Fatalf("repaired daemon did not start: %v", ctx.Err())
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", cfg["socket_path"].(string))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("http://unix/status")
	if err != nil {
		t.Fatalf("repaired daemon is unreachable: %v", err)
	}
	var status struct {
		Running bool `json:"running"`
	}
	err = json.NewDecoder(response.Body).Decode(&status)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !status.Running {
		t.Fatalf("repaired daemon status: running=%t, HTTP=%d, error=%v", status.Running, response.StatusCode, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("signal shutdown failed: %v, %s", err, logs.String())
		}
	case <-ctx.Done():
		t.Fatalf("daemon did not stop after SIGTERM: %v", ctx.Err())
	}
	if conn, err := net.DialTimeout("unix", cfg["socket_path"].(string), time.Second); err == nil {
		conn.Close()
		t.Fatal("control endpoint still accepts connections after daemon exit")
	}
}
