package collect

import (
	"context"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestDiffConnections(t *testing.T) {
	k1 := connKey{PID: 200, Host: "a.com", Port: 443}
	k2 := connKey{PID: 200, Host: "b.com", Port: 80}

	prev := map[connKey]struct{}{k1: {}}
	cur := map[connKey]struct{}{k1: {}, k2: {}}

	opened, closed := DiffConnections(prev, cur)
	if len(opened) != 1 || opened[0] != k2 {
		t.Fatalf("opened = %+v, want [%+v]", opened, k2)
	}
	if len(closed) != 0 {
		t.Fatalf("closed = %+v, want empty", closed)
	}

	// Disappearance
	cur2 := map[connKey]struct{}{}
	opened2, closed2 := DiffConnections(cur, cur2)
	if len(opened2) != 0 {
		t.Fatalf("opened2 = %+v, want empty", opened2)
	}
	if len(closed2) != 2 {
		t.Fatalf("closed2 = %+v, want 2 items", closed2)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"127.0.0.1", "127.0.0.53", "127.42.0.9", "::1", "localhost"}
	for _, h := range loopback {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	external := []string{"93.184.216.34", "160.79.104.10", "2606:4700::6810:85e5", "api.anthropic.com", ""}
	for _, h := range external {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}

type stubSockLister struct{ socks []connKey }

func (s stubSockLister) SocketsFor(pid int32) []connKey { return s.socks }

type stubProcSource struct{ procs []agents.ProcInfo }

func (s stubProcSource) List() []agents.ProcInfo { return s.procs }
func (s stubProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	for _, p := range s.procs {
		if p.PID == pid {
			return p, true
		}
	}
	return agents.ProcInfo{}, false
}

// Loopback sockets on an agent pid must never become conn events: the live
// store filled with 100% socket churn (localhost dev servers, model servers)
// and pushed every agent-semantic event out of the retention window.
func TestNetSamplerSkipsLoopback(t *testing.T) {
	procs := stubProcSource{procs: []agents.ProcInfo{
		{PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", StartTime: time.Now()},
	}}
	tagger := agents.New(config.Config{
		Agents: []config.AgentDef{{Name: "claude", Match: []string{"claude"}}},
	}, procs)
	tagger.Refresh()

	b := bus.New(64)
	sub := b.Subscribe()
	ns := NewNetSampler(b, tagger, 10*time.Millisecond, stubSockLister{socks: []connKey{
		{PID: 100, Host: "127.0.0.1", Port: 8080}, // dev server
		{PID: 100, Host: "::1", Port: 11434},      // local model server
		{PID: 100, Host: "localhost", Port: 3000}, // named loopback
		{PID: 100, Host: "93.184.216.34", Port: 443},
	}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ns.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	var got []event.Event
	for {
		select {
		case ev := <-sub:
			if ev.Kind == event.KindConnOpen {
				got = append(got, ev)
				if isLoopbackHost(ev.RemoteHost) {
					t.Fatalf("loopback connection became an event: %+v", ev)
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for the external conn event")
		}
		// One non-loopback socket is expected and sufficient: the sampler had
		// the full socket set in one snapshot, so any loopback leak would have
		// arrived alongside it.
		seen := map[string]bool{}
		for _, ev := range got {
			seen[ev.RemoteHost] = true
		}
		if seen["93.184.216.34"] && len(got) == 1 {
			return
		}
	}
}
