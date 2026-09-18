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
		{PID: 200, PPID: 1, Exe: "/usr/local/bin/cursor-agent"},
	}
}

func (f fakeProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	if pid == 200 {
		return agents.ProcInfo{PID: 200, PPID: 1, Exe: "/usr/local/bin/cursor-agent"}, true
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
	if f[0].Severity != 1 {
		t.Fatalf("severity = %d, want 1 (informational — routine keychain-db opens are not an alarm)", f[0].Severity)
	}
}

func TestUninspectedEgressCounted(t *testing.T) {
	c := newTestCorrelator(t)
	// Recent base: entries past the retention window are pruned on read.
	base := time.Now().Add(-time.Hour)

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

// A rule-level mute (host "*") silences the keychain class — the escape
// hatch for the "sea of warnings" complaint. Silenced fires are counted, so
// the quiet is deliberate and measurable, not hidden.
func TestKeychainRuleLevelMute(t *testing.T) {
	c := newTestCorrelator(t)
	c.SetMuteChecker(func(rule, host string) bool { return host == "*" })
	base := time.Now()

	if f := c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: "/Users/x/Library/Keychains/login.keychain-db"}); len(f) != 0 {
		t.Fatalf("muted keychain-access must not flag, got %+v", f)
	}
	if f := c.Observe(event.Event{Kind: event.KindExec, PID: 200, TS: base, ExePath: "/usr/bin/security"}); len(f) != 0 {
		t.Fatalf("muted keychain-security-cli must not flag, got %+v", f)
	}
	if got := c.MutedCount(); got != 2 {
		t.Fatalf("muted fires must be counted, got %d, want 2", got)
	}
}

// The rolling window counts only recent pairs: an endpoint silent for 48h is
// outside the 24h headline number but still listed in the unfiltered summary
// (until the retention sweeps it).
func TestUninspectedEgressWindow(t *testing.T) {
	c := newTestCorrelator(t)
	now := time.Now()
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: now.Add(-48 * time.Hour), RemoteHost: "old.example.com", RemotePort: 443})
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: now.Add(-time.Hour), RemoteHost: "fresh.example.com", RemotePort: 443})

	if got := c.UninspectedEgressCount(); got != 2 {
		t.Fatalf("total count = %d, want 2", got)
	}
	if got := c.UninspectedEgressCountWindow(UninspectedWindow); got != 1 {
		t.Fatalf("24h window count = %d, want 1 (only the fresh endpoint)", got)
	}
	sum := c.UninspectedEgressSummarySince(now.Add(-UninspectedWindow))
	if len(sum) != 1 || sum[0].Host != "fresh.example.com" {
		t.Fatalf("windowed summary = %+v, want only fresh.example.com", sum)
	}
}

// Pairs silent past the retention are swept so the set cannot accumulate
// dead weight for the daemon's lifetime.
func TestUninspectedRetentionPrunes(t *testing.T) {
	c := newTestCorrelator(t)
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: time.Now().Add(-8 * 24 * time.Hour), RemoteHost: "ancient.example.com", RemotePort: 443})
	if got := c.UninspectedEgressCount(); got != 0 {
		t.Fatalf("entry past retention must be pruned, count = %d", got)
	}
}

// Repeats of the same (pid, keychain path) within the window collapse to one
// flag — 20 identical rows for one access pattern was the "ignore looks
// broken" complaint.
func TestKeychainRepeatSuppression(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Now()
	path := "/Users/x/Library/Keychains/login.keychain-db"

	total := 0
	for i := 0; i < 5; i++ {
		total += len(c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base.Add(time.Duration(i) * time.Minute), Path: path}))
	}
	// One flag for the first fire; 4 repeats suppressed.
	if total != 1 {
		t.Fatalf("expected 1 flag after 5 identical accesses; got %d", total)
	}

	// After the window expires, the same pattern flags again.
	total += len(c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200,
		TS: base.Add(keychainRepeatWindow + time.Minute), Path: path}))
	if total != 2 {
		t.Fatalf("expected 2 flags after window expiry; got %d", total)
	}
}

// Repeat suppression on the other immediate-fire rules: security CLI,
// TCC tamper, and proxy hits each collapse within their window.
func TestSecurityCLIRepeatSuppression(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Now()
	total := 0
	for i := 0; i < 4; i++ {
		total += len(c.Observe(event.Event{Kind: event.KindExec, PID: 200,
			ExePath: "/usr/bin/security", TS: base.Add(time.Duration(i) * time.Minute)}))
	}
	if total != 1 {
		t.Fatalf("expected 1 flag after 4 identical security(1) execs; got %d", total)
	}
}

func TestTCCRepeatSuppression(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Now()
	total := 0
	for i := 0; i < 3; i++ {
		total += len(c.Observe(event.Event{Kind: event.KindTCCModify, PID: 200,
			TS: base.Add(time.Duration(i) * time.Minute), Detail: "kTCCServiceScreenCapture"}))
	}
	if total != 1 {
		t.Fatalf("expected 1 flag after 3 identical TCC writes; got %d", total)
	}
}

func TestProxyLeakRepeatSuppression(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Now()
	total := 0
	for i := 0; i < 4; i++ {
		total += len(c.Observe(event.Event{Kind: event.KindProxyHit, PID: 200,
			TS: base.Add(time.Duration(i) * time.Minute), RemoteHost: "evil.example.com",
			Detail: "proxy-secret-leak: aws-key in body"}))
	}
	if total != 1 {
		t.Fatalf("expected 1 flag after 4 identical leaks to the same host; got %d", total)
	}
	// A different host flags independently.
	total += len(c.Observe(event.Event{Kind: event.KindProxyHit, PID: 200,
		TS: base.Add(6 * time.Minute), RemoteHost: "other.example.com",
		Detail: "proxy-secret-leak: aws-key in body"}))
	if total != 2 {
		t.Fatalf("different host must flag independently; got %d", total)
	}
}

// Uninspected entries carry first-seen and the most recent session: the two
// facts an operator needs before "allow all" (when did this start, which run
// dialed it). Repeats update lastSeen/session but never firstSeen.
func TestUninspectedSummaryCarriesFirstSeenAndSession(t *testing.T) {
	c := newTestCorrelator(t)
	early := time.Now().Add(-2 * time.Hour)
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: early, RemoteHost: "cdn.example.com", RemotePort: 443, SessionID: "sess-a"})
	c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: time.Now().Add(-time.Minute), RemoteHost: "cdn.example.com", RemotePort: 443, SessionID: "sess-b"})

	sum := c.UninspectedEgressSummary()
	if len(sum) != 1 {
		t.Fatalf("summary = %+v, want 1 entry", sum)
	}
	if sum[0].FirstSeen.Unix() != early.Unix() {
		t.Fatalf("first_seen = %v, want the first sighting %v", sum[0].FirstSeen, early)
	}
	if sum[0].SessionID != "sess-b" {
		t.Fatalf("session_id = %q, want the most recent sess-b", sum[0].SessionID)
	}
	if sum[0].Count != 2 {
		t.Fatalf("count = %d, want 2", sum[0].Count)
	}
}
