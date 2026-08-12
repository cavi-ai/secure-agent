package correlate

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

type fakeProcSource struct{}

func (f fakeProcSource) List() []agents.ProcInfo {
	return []agents.ProcInfo{
		{PID: 200, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"},
	}
}

func (f fakeProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 200 {
		return agents.ProcInfo{PID: 200, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"}, true
	}
	return agents.ProcInfo{}, false
}

func newTestCorrelator(t *testing.T) *Correlator {
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	ps := fakeProcSource{}
	tg := agents.New(cfg, ps)
	tg.Refresh()
	cl := sensitive.New(cfg)
	return New(tg, cl, cfg)
}

func TestSensitiveReadThenForeignConnectFlags(t *testing.T) {
	c := newTestCorrelator(t) // tagger says pid 200 = "cursor"; classifier from defaults
	base := time.Unix(1_700_000_000, 0)

	// 1. cursor reads a .env — no flag yet, just remembered.
	f := c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: "/Users/x/proj/.env"})
	if len(f) != 0 {
		t.Fatalf("read alone should not flag, got %v", f)
	}

	// 2. cursor connects to a NON-vendor host 3s later — must flag.
	f = c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(3 * time.Second), RemoteHost: "evil.example.com", RemotePort: 443})
	if len(f) != 1 || f[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("expected 1 sensitive-read-then-connect flag, got %+v", f)
	}
	if f[0].Severity != 3 {
		t.Fatalf("severity = %d, want 3", f[0].Severity)
	}
}

func TestConnectToVendorHostDoesNotFlag(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: "/Users/x/proj/.env"})

	f := c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(2 * time.Second), RemoteHost: "api2.cursor.com", RemotePort: 443})
	if len(f) != 0 {
		t.Fatalf("connect to vendor host must not flag, got %+v", f)
	}
}

func TestReadThenConnectOutsideWindowDoesNotFlag(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: "/Users/x/proj/.env"})

	f := c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(10 * time.Minute), RemoteHost: "evil.example.com", RemotePort: 443})
	if len(f) != 0 {
		t.Fatalf("connect long after read must not flag, got %+v", f)
	}
}

func TestKeychainAccessFlagsImmediately(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)

	f := c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: "/Users/x/Library/Keychains/login.keychain-db"})
	if len(f) != 1 || f[0].Rule != "keychain-access" {
		t.Fatalf("expected 1 keychain-access flag, got %+v", f)
	}
	if f[0].Severity != 2 {
		t.Fatalf("severity = %d, want 2", f[0].Severity)
	}
}
