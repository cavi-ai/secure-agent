//go:build darwin

package collect

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// hangingTool writes an executable that never answers.
func hangingTool(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n/bin/sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func shortProbes(t *testing.T) {
	t.Helper()
	old := probeTimeout
	probeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { probeTimeout = old })
}

// A hung lsof (a stale network mount) must not pin the network sampler.
func TestSocketsForGivesUpOnAHungLsof(t *testing.T) {
	shortProbes(t)
	t.Setenv("PATH", filepath.Dir(hangingTool(t, "lsof")))
	done := make(chan []connKey, 1)
	go func() { done <- (&DarwinSocketLister{}).SocketsFor(0) }()
	select {
	case got := <-done:
		if len(got) != 0 {
			t.Fatalf("sockets from a hung lsof: %v", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a hung lsof blocked the sampler")
	}
}

// A hung launchctl must not hang /status, and an unanswered probe is not
// reported as a missing service.
func TestESServiceStateGivesUpOnAHungLaunchctl(t *testing.T) {
	shortProbes(t)
	old := launchctlPath
	launchctlPath = hangingTool(t, "launchctl")
	t.Cleanup(func() { launchctlPath = old })
	type result struct {
		s   ESServiceSnapshot
		err error
	}
	done := make(chan result, 1)
	go func() { s, err := ESServiceState(); done <- result{s, err} }()
	select {
	case r := <-done:
		if r.err == nil || r.s.State == "not-loaded" {
			t.Fatalf("hung launchctl: state=%q err=%v, want an error and no state", r.s.State, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a hung launchctl blocked the status probe")
	}
}
