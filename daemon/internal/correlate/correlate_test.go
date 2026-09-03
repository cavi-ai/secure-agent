package correlate

import (
	"strings"
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

func TestUninspectedEgressCounted(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)

	// Lone foreign connect: counted as uninspected egress, but produces no flag.
	f := c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base, RemoteHost: "evil.example.com", RemotePort: 443})
	if len(f) != 0 {
		t.Fatalf("lone foreign connect must not flag, got %+v", f)
	}
	if got := c.UninspectedEgressCount(); got != 1 {
		t.Fatalf("uninspected count = %d, want 1", got)
	}

	// Connecting to the local proxy (127.0.0.1) is inspected traffic — not counted.
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(time.Second), RemoteHost: "127.0.0.1", RemotePort: 8443})
	if got := c.UninspectedEgressCount(); got != 1 {
		t.Fatalf("localhost connect must not count, got %d", got)
	}

	// A vendor host is expected egress — not counted.
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(2 * time.Second), RemoteHost: "api2.cursor.com", RemotePort: 443})
	if got := c.UninspectedEgressCount(); got != 1 {
		t.Fatalf("vendor host must not count, got %d", got)
	}

	// Same foreign host again is deduped.
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base.Add(3 * time.Second), RemoteHost: "evil.example.com", RemotePort: 443})
	if got := c.UninspectedEgressCount(); got != 1 {
		t.Fatalf("dedup failed, count = %d", got)
	}
}

func TestForeignConnectThenSensitiveReadFlags(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)

	f := c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: base, RemoteHost: "evil.example.com", RemotePort: 443})
	if len(f) != 0 {
		t.Fatalf("conn alone should not flag, got %v", f)
	}

	f = c.Observe(event.Event{Kind: event.KindPluginAction, PID: 200, TS: base.Add(2 * time.Second), Path: "/Users/x/proj/.env"})
	if len(f) != 1 || f[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("expected 1 sensitive-read-then-connect flag when conn arrives before read, got %+v", f)
	}
}

func TestTCCTamperFlagsImmediately(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)

	flags := c.Observe(event.Event{
		Kind: event.KindTCCModify, PID: 200, TS: base,
		Detail: "kTCCServiceScreenCapture",
	})
	if len(flags) != 1 {
		t.Fatalf("tcc modify produced %d flags, want 1", len(flags))
	}
	f := flags[0]
	if f.Rule != "tcc-tamper" || f.Severity != 3 {
		t.Fatalf("flag = %s sev %d, want tcc-tamper/3", f.Rule, f.Severity)
	}
	if !strings.Contains(f.Evidence[0], "kTCCServiceScreenCapture") {
		t.Fatalf("evidence missing service: %v", f.Evidence)
	}
}

func TestTCCTamperIgnoredForNonAgents(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)

	// PID 999 is not in the fake proc source.
	flags := c.Observe(event.Event{
		Kind: event.KindTCCModify, PID: 999, TS: base, Detail: "kTCCServiceAccessibility",
	})
	if len(flags) != 0 {
		t.Fatalf("non-agent TCC event flagged: %+v", flags)
	}
}

func TestKeychainSecurityCLIFlagsImmediately(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)

	flags := c.Observe(event.Event{
		Kind:    event.KindExec,
		PID:     200,
		TS:      base,
		ExePath: "/usr/bin/security",
	})
	if len(flags) != 1 {
		t.Fatalf("security(1) exec produced %d flags, want 1", len(flags))
	}
	f := flags[0]
	if f.Rule != "keychain-security-cli" || f.Severity != 3 {
		t.Fatalf("flag = %s sev %d, want keychain-security-cli/3", f.Rule, f.Severity)
	}
	if !strings.Contains(f.Evidence[0], "/usr/bin/security") {
		t.Fatalf("evidence missing exe path: %v", f.Evidence)
	}
}

func TestKeychainCLIRuleIgnoresOtherExecs(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)

	for _, exe := range []string{"/usr/bin/git", "/bin/zsh", "/usr/bin/securityctl"} {
		flags := c.Observe(event.Event{Kind: event.KindExec, PID: 200, TS: base, ExePath: exe})
		if len(flags) != 0 {
			t.Fatalf("%s must not flag: %+v", exe, flags)
		}
	}
}
