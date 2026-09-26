package correlate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

func homePath(t *testing.T, rel string) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(home, rel)
}

func readThenConnect(c *Correlator, path string, at time.Time) []model.Flag {
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: at, Path: path})
	return c.Observe(event.Event{Kind: event.KindConnOpen, PID: 200, TS: at.Add(2 * time.Second), RemoteHost: "evil.example.com", RemotePort: 443})
}

// Shell rc files and harness settings are read on every shell or harness
// start: reading one, then connecting out, is not a secret read.
func TestStartupConfigReadThenConnectDoesNotFlag(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	for i, rel := range []string{".zshenv", ".zshrc", ".claude/settings.json"} {
		if f := readThenConnect(c, homePath(t, rel), base.Add(time.Duration(i)*time.Minute)); len(f) != 0 {
			t.Fatalf("read of ~/%s then connect flagged: %+v", rel, f)
		}
	}
}

func TestSecretReadThenConnectStillFlagsWithProcess(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	for i, rel := range []string{".aws/credentials", ".netrc"} {
		f := readThenConnect(c, homePath(t, rel), base.Add(time.Duration(i)*time.Minute))
		if len(f) != 1 || f[0].Rule != "sensitive-read-then-connect" {
			t.Fatalf("read of ~/%s then connect: flags = %+v, want 1", rel, f)
		}
		if p := f[0].Process; p == nil || p.Name != "cursor-agent" || p.Exe != "/usr/local/bin/cursor-agent" || p.PPID != 1 {
			t.Fatalf("raised flag process = %+v, want the cursor-agent snapshot", p)
		}
	}
}

func TestStaleReadFlagIDs(t *testing.T) {
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	cl := sensitive.New(cfg)
	read := func(path, rule string) []model.EvidenceItem {
		return []model.EvidenceItem{{Kind: "read", Label: path, Rule: rule}, {Kind: "connect", Label: "evil.example.com:443"}}
	}
	zshenv := homePath(t, ".zshenv")
	flags := []model.Flag{
		{ID: "stale", Rule: "sensitive-read-then-connect", Evidence: read(zshenv, "glob:"+zshenv)},
		{ID: "stale-settings", Rule: "sensitive-read-then-connect", Evidence: read(homePath(t, ".claude/settings.json"), "glob:~/.claude/settings.json")},
		{ID: "acked", Rule: "sensitive-read-then-connect", Acknowledged: true, Evidence: read(zshenv, "glob:"+zshenv)},
		{ID: "aws", Rule: "sensitive-read-then-connect", Evidence: read(homePath(t, ".aws/credentials"), "aws")},
		{ID: "netrc", Rule: "sensitive-read-then-connect", Evidence: read(homePath(t, ".netrc"), "glob:~/.netrc")},
		{ID: "other-rule", Rule: "keychain-access", Evidence: read(zshenv, "glob:"+zshenv)},
		{ID: "legacy", Rule: "sensitive-read-then-connect", Evidence: model.EvidenceFromStrings("cursor read " + zshenv)},
	}
	got := StaleReadFlagIDs(flags, cl)
	if len(got) != 2 || got[0] != "stale" || got[1] != "stale-settings" {
		t.Fatalf("stale ids = %v, want [stale stale-settings]", got)
	}
}

// familyProcSource: cursor-agent (200) with a gh child (201), gh's own
// child git-remote-https (202), and gh's sibling node (203).
type familyProcSource struct{}

var familyProcs = []agents.ProcInfo{
	{PID: 200, PPID: 1, Exe: "/usr/local/bin/cursor-agent"},
	{PID: 201, PPID: 200, Exe: "/opt/homebrew/bin/gh"},
	{PID: 202, PPID: 201, Exe: "/usr/libexec/git-core/git-remote-https"},
	{PID: 203, PPID: 200, Exe: "/usr/local/bin/node"},
}

func (familyProcSource) List() []agents.ProcInfo { return familyProcs }

func (familyProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	for _, p := range familyProcs {
		if p.PID == pid {
			return p, true
		}
	}
	return agents.ProcInfo{}, false
}

func newFamilyCorrelator(t *testing.T) *Correlator {
	t.Helper()
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, familyProcSource{})
	tg.Refresh()
	return New(tg, sensitive.New(cfg), cfg)
}

func connect(c *Correlator, pid int32, at time.Time) []model.Flag {
	return c.Observe(event.Event{Kind: event.KindConnOpen, PID: pid, TS: at, RemoteHost: "evil.example.com", RemotePort: 443})
}

func countRule(flags []model.Flag, rule string) int {
	n := 0
	for _, f := range flags {
		if f.Rule == rule {
			n++
		}
	}
	return n
}

// Every TLS client reads the trust store; reading it before or after a
// connect is never a secret read.
func TestTrustStoreReadNeverSeedsReadThenConnect(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	for i, path := range []string{"/System/Library/Keychains/SystemTrustSettings.plist", "/System/Library/Keychains/SystemRootCertificates.keychain"} {
		at := base.Add(time.Duration(i) * 5 * time.Minute)
		read := event.Event{Kind: event.KindFileOpen, PID: 200, TS: at, Path: path, ExePath: "/usr/local/bin/cursor-agent"}
		if f := c.Observe(read); len(f) != 0 {
			t.Fatalf("trust read of %s flagged: %+v", path, f)
		}
		if f := connect(c, 200, at.Add(2*time.Second)); len(f) != 0 {
			t.Fatalf("connect after trust read of %s flagged: %+v", path, f)
		}
		read.TS = at.Add(3 * time.Second)
		if f := c.Observe(read); len(f) != 0 {
			t.Fatalf("trust read of %s after connect flagged: %+v", path, f)
		}
	}
}

// A TLS client opening a keychain file is certificate lookup: keychain-access
// records it, read-then-connect does not fire.
func TestKeychainFileOpenForTLSDoesNotSeed(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	f := c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: "/Users/x/Library/Keychains/login.keychain-db", ExePath: "/usr/local/bin/cursor-agent"})
	if countRule(f, "keychain-access") != 1 {
		t.Fatalf("keychain open must still raise keychain-access, got %+v", f)
	}
	if f := connect(c, 200, base.Add(2*time.Second)); len(f) != 0 {
		t.Fatalf("connect after a TLS keychain open flagged: %+v", f)
	}
}

// A byte-copy tool opening a keychain file, or an agent tool reading one,
// is a secret read: a connect within the window flags.
func TestKeychainFileCopiedThenConnectFlags(t *testing.T) {
	cases := []event.Event{
		{Kind: event.KindFileOpen, PID: 200, Path: "/Users/x/Library/Keychains/login.keychain-db", ExePath: "/bin/cat"},
		{Kind: event.KindPluginAction, PID: 200, Path: "/Users/x/Library/Keychains/login.keychain-db"},
	}
	for _, read := range cases {
		c := newTestCorrelator(t)
		base := time.Unix(1_700_000_000, 0)
		read.TS = base
		c.Observe(read)
		f := connect(c, 200, base.Add(2*time.Second))
		if countRule(f, "sensitive-read-then-connect") != 1 {
			t.Fatalf("%s read by %q then connect: flags = %+v, want 1 read-then-connect", read.Kind, read.ExePath, f)
		}
		if got := f[0].Evidence[0]; got.Exe != read.ExePath || got.PID != 200 {
			t.Fatalf("read evidence reader = pid %d exe %q, want pid 200 exe %q", got.PID, got.Exe, read.ExePath)
		}
	}
}

// When one process reads and another connects, the read evidence names the
// reader, not the connector.
func TestReadEvidenceNamesTheReader(t *testing.T) {
	c := newFamilyCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 201, TS: base, Path: "/Users/x/.aws/credentials", ExePath: "/opt/homebrew/bin/gh"})
	f := connect(c, 200, base.Add(2*time.Second))
	if len(f) != 1 || f[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("flags = %+v, want 1 read-then-connect", f)
	}
	read := f[0].Evidence[0]
	if read.PID != 201 || read.Exe != "/opt/homebrew/bin/gh" || !strings.Contains(read.Text, "(pid 201)") {
		t.Fatalf("read evidence = %+v, want reader pid 201 /opt/homebrew/bin/gh", read)
	}
	if f[0].PID != 200 {
		t.Fatalf("flag pid = %d, want the connector 200", f[0].PID)
	}
}

func TestStaleReadFlagIDsJudgesEveryRead(t *testing.T) {
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	cl := sensitive.New(cfg)
	conn := model.EvidenceItem{Kind: "connect", Label: "evil.example.com:443"}
	trust := model.EvidenceItem{Kind: "read", Label: "/System/Library/Keychains/SystemTrustSettings.plist", Rule: "system-trust"}
	login := model.EvidenceItem{Kind: "read", Label: "/Users/x/Library/Keychains/login.keychain-db", Rule: "keychain:library/keychains"}
	loginByCat := login
	loginByCat.Exe = "/bin/cat"
	aws := model.EvidenceItem{Kind: "read", Label: homePath(t, ".aws/credentials"), Rule: "aws"}
	flag := func(id string, proc *model.FlagProcess, ev ...model.EvidenceItem) model.Flag {
		return model.Flag{ID: id, Rule: "sensitive-read-then-connect", Process: proc, Evidence: append(ev, conn)}
	}
	flags := []model.Flag{
		flag("trust", nil, trust),
		flag("trust+login", &model.FlagProcess{Exe: "/opt/homebrew/bin/codex"}, trust, login),
		flag("login-by-cat", nil, loginByCat),
		flag("login-legacy-cat", &model.FlagProcess{Exe: "/bin/cat"}, login),
		flag("trust+aws", nil, trust, aws),
		flag("aws+trust", nil, aws, trust),
	}
	got := StaleReadFlagIDs(flags, cl)
	if strings.Join(got, ",") != "trust,trust+login" {
		t.Fatalf("stale ids = %v, want [trust trust+login]", got)
	}
}
