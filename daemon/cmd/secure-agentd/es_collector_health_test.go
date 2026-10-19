package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
)

func TestESPermissionFailureRequiresClientAuthorizationDenial(t *testing.T) {
	for _, tc := range []struct {
		message string
		want    bool
	}{
		{"ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED", true},
		{"responsible process needs TCC Full Disk Access authorization", true},
		{"spool write: operation not permitted", false},
		{"start eslogger: permission denied", false},
	} {
		if got := isESPermissionFailure(errors.New(tc.message)); got != tc.want {
			t.Fatalf("isESPermissionFailure(%q) = %v", tc.message, got)
		}
	}
}

func readCollectorHealth(t *testing.T, path, state string) collect.ESCollectorStatus {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(path)
		var status collect.ESCollectorStatus
		if json.Unmarshal(data, &status) == nil && status.State == state {
			return status
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("collector did not publish %s", state)
	return collect.ESCollectorStatus{}
}

func TestCollectorHealthPublishesDenialDeliveryAndHeartbeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	h := newESCollectorHealth(path, 42, 10*time.Millisecond)
	defer h.Close()
	h.setState("permission_denied")
	denied := readCollectorHealth(t, path, "permission_denied")
	if denied.PID != 42 || denied.LastDeliveryAt != nil {
		t.Fatalf("denied collector claimed delivery: %+v", denied)
	}
	// The privileged helper must supply its own executable metadata: the
	// unprivileged daemon cannot always inspect a root SMAppService process.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		HelperMtime time.Time `json:"helper_mtime"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	if !metadata.HelperMtime.Equal(info.ModTime()) {
		t.Fatalf("helper did not publish executable mtime: %s", data)
	}
	h.delivered()
	active := readCollectorHealth(t, path, "collecting")
	if active.LastDeliveryAt == nil || active.LastDeliveryAt.Before(denied.UpdatedAt) {
		t.Fatalf("delivery missing: %+v", active)
	}
	deadline := time.Now().Add(time.Second)
	for !readCollectorHealth(t, path, "collecting").UpdatedAt.After(active.UpdatedAt) {
		if time.Now().After(deadline) {
			t.Fatal("collector heartbeat did not advance")
		}
		time.Sleep(5 * time.Millisecond)
	}
	info, err = os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("health file permissions: %v %v", info, err)
	}
}

func TestCollectorCommandReportsPermissionFailure(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_ES_DENIAL") == "1" {
		os.Stderr.WriteString("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: Not permitted to create an ES Client")
		os.Exit(1)
	}
	root := t.TempDir()
	h := newESCollectorHealth(filepath.Join(root, "status.json"), os.Getpid(), time.Second)
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCollectorCommandReportsPermissionFailure$")
	cmd.Env = append(os.Environ(), "SECURE_AGENT_TEST_ES_DENIAL=1")
	err := runESLoggerCommand(ctx, cmd, h, filepath.Join(root, "spool.jsonl"))
	if !isESPermissionFailure(err) {
		t.Fatalf("expected ES permission refusal: %v", err)
	}
	status := readCollectorHealth(t, filepath.Join(root, "status.json"), "permission_denied")
	if status.LastDeliveryAt != nil {
		t.Fatalf("failed command claimed delivery: %+v", status)
	}
}

func TestCollectorCommandReportsPersistedDelivery(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_ES_DELIVERY") == "1" {
		os.Stdout.WriteString(esRecord(time.Now().UTC()) + "\n")
		os.Exit(0)
	}
	root := t.TempDir()
	path := filepath.Join(root, "status.json")
	h := newESCollectorHealth(path, os.Getpid(), time.Second)
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCollectorCommandReportsPersistedDelivery$")
	cmd.Env = append(os.Environ(), "SECURE_AGENT_TEST_ES_DELIVERY=1")
	spool := filepath.Join(root, "spool.jsonl")
	if err := runESLoggerCommand(ctx, cmd, h, spool); err != nil {
		t.Fatal(err)
	}
	status := readCollectorHealth(t, path, "stopped")
	data, err := os.ReadFile(spool)
	if err != nil || len(data) == 0 || status.LastDeliveryAt == nil {
		t.Fatalf("missing persisted delivery: %+v bytes=%d err=%v", status, len(data), err)
	}
}
