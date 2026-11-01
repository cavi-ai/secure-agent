package collect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// sampler builds a NetSampler over socks for agent pid 100, with lookup as
// its reverse resolver.
func sampler(t *testing.T, socks *[]connKey, lookup func(context.Context, string) ([]string, error)) (*NetSampler, <-chan event.Event) {
	t.Helper()
	procs := stubProcSource{procs: []agents.ProcInfo{{PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", StartTime: time.Now()}}}
	tagger := agents.New(config.Config{Agents: []config.AgentDef{{Name: "claude", Match: []string{"claude"}}}}, procs)
	tagger.Refresh()
	b := bus.New(64)
	sub := b.Subscribe()
	ns := NewNetSampler(b, tagger, time.Hour, funcSockLister(func() []connKey { return *socks }))
	ns.lookupAddr = lookup
	return ns, sub
}

type funcSockLister func() []connKey

func (f funcSockLister) SocketsFor(int32) []connKey { return f() }

func drain(sub <-chan event.Event) []event.Event {
	var out []event.Event
	for {
		select {
		case e := <-sub:
			out = append(out, e)
		default:
			return out
		}
	}
}

// A connection opens once and closes once, named by the host its address
// resolves to: the name arriving after the first sample does not read as the
// connection closing and reopening.
func TestNetSamplerKeysConnectionsByAddress(t *testing.T) {
	socks := []connKey{{PID: 100, Host: "140.82.112.3", Port: 443}}
	resolved := make(chan struct{})
	ns, sub := sampler(t, &socks, func(context.Context, string) ([]string, error) {
		defer close(resolved)
		return []string{"lb-140-82-112-3-iad.github.com."}, nil
	})
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if n := ns.step(t0); n != 0 {
		t.Fatalf("first sample published %d events before the address resolved", n)
	}
	<-resolved
	for i := 1; i <= 3; i++ {
		ns.step(t0.Add(time.Duration(i) * 2 * time.Second))
	}
	got := drain(sub)
	if len(got) != 1 || got[0].Kind != event.KindConnOpen || got[0].RemoteHost != "lb-140-82-112-3-iad.github.com" || !got[0].TS.Equal(t0) {
		t.Fatalf("events = %+v, want one open naming the host, stamped at the first sample", got)
	}
	socks = nil
	ns.step(t0.Add(10 * time.Second))
	if got := drain(sub); len(got) != 1 || got[0].Kind != event.KindConnClose || got[0].RemoteHost != "lb-140-82-112-3-iad.github.com" {
		t.Fatalf("close = %+v, want one close under the opened name", got)
	}
}

// A connection that closes before its address resolves still gets its open,
// stamped when it was first sampled, and its close.
func TestNetSamplerPublishesAShortConnection(t *testing.T) {
	socks := []connKey{{PID: 100, Host: "203.0.113.9", Port: 443}}
	block := make(chan struct{})
	defer close(block)
	ns, sub := sampler(t, &socks, func(ctx context.Context, _ string) ([]string, error) {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return nil, ctx.Err()
	})
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	ns.step(t0)
	socks = nil
	ns.step(t0.Add(2 * time.Second))
	got := drain(sub)
	if len(got) != 2 || got[0].Kind != event.KindConnOpen || !got[0].TS.Equal(t0) || got[1].Kind != event.KindConnClose || got[0].RemoteHost != "203.0.113.9" {
		t.Fatalf("events = %+v, want the open (at the first sample, by address) then the close", got)
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
	ns.lookupAddr = func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR record") }

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
