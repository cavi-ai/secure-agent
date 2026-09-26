package correlate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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
