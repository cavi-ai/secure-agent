package advisor

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestManagedModelStartsOnDemandAndReapsOnIdle(t *testing.T) {
	m, err := NewManagedTransport(ManagedSpec{Model: "fake-4b", Bin: fakeModelServer(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.idle = 20 * time.Millisecond
	if m.loaded() || m.ProtectionStatus().State != "unloaded" {
		t.Fatal("model started during configuration")
	}
	var directories []string
	call := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1/v1/chat/completions", strings.NewReader(`{}`))
		resp, err := m.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if status := m.ProtectionStatus(); status.Transport != "inherited-unix-v1" || status.State != "running" {
			t.Fatalf("private transport not established: %+v", status)
		}
		directories = append(directories, m.process.directory)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	call()
	deadline := time.Now().Add(time.Second)
	for m.loaded() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.loaded() || m.ProtectionStatus().State != "unloaded" {
		t.Fatal("idle model process survived expiry")
	}
	call()
	if !m.loaded() {
		t.Fatal("expired model could not restart on demand")
	}
	m.Close()
	if m.loaded() || m.ProtectionStatus().State != "closed" {
		t.Fatal("closed model retained its process")
	}
	for _, directory := range directories {
		if _, err := os.Stat(directory); !os.IsNotExist(err) {
			t.Fatalf("private socket directory retained: %v", err)
		}
	}
}

func TestManagedTransportRefusesLegacyProtocol(t *testing.T) {
	bin := t.TempDir() + "/mlx-agent"
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s' '{\"protocol\":\"legacy-tcp\"}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManagedTransport(ManagedSpec{Model: "fixture", Bin: bin}); err == nil {
		t.Fatal("legacy TCP fallback accepted")
	}
}
