package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"golang.org/x/sys/unix"
)

// Run the actual CLI entry point in a child so fatal startup errors and
// signal-driven shutdown are tested without terminating the test runner.
func TestDaemonProcessHelper(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_MAIN") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("secure-agentd", flag.ExitOnError)
	os.Args = []string{"secure-agentd", "--config", os.Getenv("SECURE_AGENT_TEST_CONFIG")}
	if os.Getenv("SECURE_AGENT_TEST_REPORT_SOCKET") == "1" {
		os.Args = append(os.Args, "--owner-pid-version", "1", "--report-owner-socket")
	}
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

func TestDaemonReportsConfiguredSocketToOwner(t *testing.T) {
	dir, cfg := lifecycleFixture(t)
	path := cfg["socket_path"].(string)
	cfg["socket_path"] = "$SECURE_AGENT_TEST_SOCKET"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := daemonCommand(ctx, dir, writeLifecycleConfig(t, dir, cfg))
	cmd.Env = append(cmd.Env, "SECURE_AGENT_TEST_REPORT_SOCKET=1", "SECURE_AGENT_TEST_SOCKET="+path)
	if os.Getenv("SECURE_AGENT_LIFECYCLE_BINARY") != "" {
		cmd.Args = append(cmd.Args, "--owner-pid-version", "1", "--report-owner-socket")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(pair[0])
	unix.CloseOnExec(pair[1])
	parent := os.NewFile(uintptr(pair[0]), "parent")
	defer parent.Close()
	child := os.NewFile(uintptr(pair[1]), "child")
	defer child.Close()
	conn, err := net.FileConn(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = child
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child.Close()
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("daemon log: %s", &logs)
		}
	}()
	var datagram [2048]byte
	n, err := conn.Read(datagram[:])
	if err != nil {
		t.Fatalf("read socket report: %v", err)
	}
	var report struct {
		Path       string
		PID        int32
		UID        int
		PIDVersion uint32
	}
	if err := json.Unmarshal(datagram[:n], &report); err != nil {
		t.Fatal(err)
	}
	if report.Path != path || report.PID != int32(cmd.Process.Pid) {
		t.Fatalf("report = %+v, want configured socket %q and child pid %d", report, path, cmd.Process.Pid)
	}
	control, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	peer, err := api.NewPeerChecker().PeerCred(control)
	if err != nil || peer.PID != report.PID || peer.UID != report.UID || peer.PIDVersion != report.PIDVersion {
		t.Fatalf("control peer = %+v, %v; report specifies %+v", peer, err, report)
	}
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
	lease, err := os.OpenFile(cfg["socket_path"].(string)+".headless.lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	leaseFD := int(lease.Fd())
	if err := unix.Flock(leaseFD, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("running headless daemon should hold the hook lease: %v", err)
	}
	decision := make(chan error, 1)
	go func() {
		res, err := client.Post("http://unix/guard/decision", "application/json",
			strings.NewReader(`{"agent":"claude","tool":"Read","path":"/fixture/.env","rule_id":"env-files"}`))
		if err == nil {
			defer res.Body.Close()
			if res.StatusCode != http.StatusServiceUnavailable {
				err = fmt.Errorf("pending request completed with HTTP %d, want 503 after shutdown", res.StatusCode)
			} else if lockErr := unix.Flock(leaseFD, unix.LOCK_EX|unix.LOCK_NB); lockErr != nil {
				err = fmt.Errorf("pending request failed while hooks still saw an active headless daemon: %w", lockErr)
			}
		}
		decision <- err
	}()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		res, err := client.Get("http://unix/guard/pending")
		if err != nil {
			t.Fatal(err)
		}
		var pending []struct{ ID string }
		err = json.NewDecoder(res.Body).Decode(&pending)
		res.Body.Close()
		if err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("read pending requests: HTTP %d, %v", res.StatusCode, err)
		}
		if len(pending) == 1 && pending[0].ID != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("guard request did not reach the daemon")
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := <-decision; err != nil {
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
