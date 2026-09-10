package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/fleet"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func TestGuardBrokerMS(t *testing.T) {
	cases := []struct {
		name string
		hook int
		want int
	}{
		{"default when unset", 0, 42000},
		{"default when negative", -5, 42000},
		{"3s shorter than hook", 45000, 42000},
		{"floored at 1s", 3000, 1000},
		{"tiny hook still floored", 100, 1000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := guardBrokerMS(c.hook); got != c.want {
				t.Fatalf("guardBrokerMS(%d) = %d, want %d", c.hook, got, c.want)
			}
		})
	}
}

func TestTranscriptTailTargets(t *testing.T) {
	base := transcriptTailTargets("/home/x", "")
	if len(base) != 4 {
		t.Fatalf("expected 4 base targets, got %d: %v", len(base), base)
	}
	withJSONL := transcriptTailTargets("/home/x", "/var/log/events.jsonl")
	if len(withJSONL) != 5 || withJSONL[4] != "/var/log/events.jsonl" {
		t.Fatalf("jsonl path not appended: %v", withJSONL)
	}
}

func TestBuildStatusFn(t *testing.T) {
	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, treeProcSource{})
	tagger.Refresh()
	cr := correlate.New(tagger, sensitive.New(cfg), cfg)
	reg := supervise.NewRegistry()

	fn := buildStatusFn(nil, tagger, cr, nil, reg, time.Now().Add(-2*time.Second), true)
	s := fn()

	if !s.Running {
		t.Fatal("status should report running")
	}
	if !s.AdvisorEnabled {
		t.Fatal("status must carry the advisor opt-in state")
	}
	if s.Version == "" {
		t.Fatal("status must carry the build version (console badge reads it)")
	}
	if s.Uptime == "" || s.Uptime == "0s" {
		t.Fatalf("uptime should reflect the start time, got %q", s.Uptime)
	}
	// Roots vs processes: pid 500 is the tree root, 501 its helper child —
	// one agent, two tracked processes. (266 processes ≠ 266 agents.)
	if s.ActiveAgents != 1 {
		t.Fatalf("ActiveAgents = %d, want 1 root", s.ActiveAgents)
	}
	if s.TrackedProcesses != 2 {
		t.Fatalf("TrackedProcesses = %d, want 2", s.TrackedProcesses)
	}
	if s.ProxyEnabled || s.ProxyPort != 0 {
		t.Fatalf("nil proxy must report disabled/0, got %v/%d", s.ProxyEnabled, s.ProxyPort)
	}
	if s.FirewallStats != nil {
		t.Fatalf("nil engine must report nil stats, got %v", s.FirewallStats)
	}
}

// treeProcSource is a one-tree process list: cursor root (500) + zsh helper
// child (501) — the shape that used to count as two "agents".
type treeProcSource struct{}

func (treeProcSource) List() []agents.ProcInfo {
	return []agents.ProcInfo{
		{PID: 500, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"},
		{PID: 501, PPID: 500, Comm: "zsh"},
	}
}

func (treeProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 500 {
		return agents.ProcInfo{PID: 500, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"}, true
	}
	return agents.ProcInfo{}, false
}

// The extracted drain loop: bus events must be persisted, correlated, and the
// done channel must close once the bus closes (shutdown waits on it).
func TestStartDrainLoopPersistsAndCloses(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg, _ := config.Load("/nonexistent")
	tagger := agents.New(cfg, fakeProcSource{})
	tagger.Refresh()
	cr := correlate.New(tagger, sensitive.New(cfg), cfg)

	b := bus.New(64)
	done := startDrainLoop(b.Subscribe(), st, cr, fleet.NewPublisher(), nil)

	now := time.Now()
	b.Publish(event.Event{Kind: event.KindPluginAction, TS: now, PID: 500, Path: "/Users/x/project/.env"})
	time.Sleep(50 * time.Millisecond)
	b.Publish(event.Event{Kind: event.KindConnOpen, TS: now.Add(100 * time.Millisecond), PID: 500, RemoteHost: "evil.example.com", RemotePort: 443})

	b.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain loop did not finish after bus close")
	}

	flags := st.RecentFlags(10)
	if len(flags) != 1 || flags[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("expected the correlated flag persisted, got %v", flags)
	}
	incidents := st.RecentIncidents(10)
	if len(incidents) == 0 {
		t.Fatal("drain loop must turn the flag into an incident report")
	}
}

func TestWatchParentExit(t *testing.T) {
	if ch := watchParentExit(1); ch != nil {
		t.Fatal("pid-1 launch must not start an orphan watch")
	}
}
