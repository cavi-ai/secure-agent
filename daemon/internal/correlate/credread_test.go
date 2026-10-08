package correlate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// twoRootSource: two cursor-agent roots (200, 300), each with one child.
type twoRootSource struct{}

var twoRootProcs = []agents.ProcInfo{
	{PID: 200, PPID: 1, Exe: "/usr/local/bin/cursor-agent"},
	{PID: 210, PPID: 200, Exe: "/bin/zsh"},
	{PID: 300, PPID: 1, Exe: "/usr/local/bin/cursor-agent"},
	{PID: 310, PPID: 300, Exe: "/bin/zsh"},
}

func (twoRootSource) List() []agents.ProcInfo { return twoRootProcs }

func (twoRootSource) Info(pid int32) (agents.ProcInfo, bool) {
	for _, p := range twoRootProcs {
		if p.PID == pid {
			return p, true
		}
	}
	return agents.ProcInfo{}, false
}

func newTwoRootCorrelator(t *testing.T) *Correlator {
	t.Helper()
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, twoRootSource{})
	tg.Refresh()
	return New(tg, sensitive.New(cfg), cfg)
}

const (
	modeFile = 0o100644
	modeDir  = 0o040755
)

func openEv(pid int32, exe, path string, flags int32, mode uint32, ino uint64, birth int64, at time.Time) event.Event {
	return event.Event{Kind: event.KindFileOpen, PID: pid, ExePath: exe, Path: path, TS: at,
		OpenFlags: flags, FileMode: mode, FileIno: ino, FileBirth: birth}
}

func connectEv(pid int32, host string, at time.Time) event.Event {
	return event.Event{Kind: event.KindConnOpen, PID: pid, TS: at, RemoteHost: host, RemotePort: 443}
}

func flagsFor(c *Correlator, evs ...event.Event) []model.Flag {
	var out []model.Flag
	for _, e := range evs {
		out = append(out, c.Observe(e)...)
	}
	return out
}

func TestDirectoryOpenIsNotARead(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	dir := homePath(t, ".docker")
	run := func(mode uint32) []model.Flag {
		c := newTwoRootCorrelator(t)
		return flagsFor(c,
			openEv(210, "/bin/zsh", dir, event.OpenRead, mode, 5, 6, base),
			connectEv(210, "evil.example.com", base.Add(time.Second)))
	}
	if f := run(modeDir); len(f) != 0 {
		t.Fatalf("directory open flagged: %+v", f)
	}
	if f := run(0); len(f) != 1 {
		t.Fatalf("open of unknown mode: flags = %d, want 1", len(f))
	}
}

func TestWriteOnlyOpenIsNotARead(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	path := homePath(t, ".netrc")
	run := func(flags int32) []model.Flag {
		c := newTwoRootCorrelator(t)
		return flagsFor(c,
			openEv(210, "/usr/bin/tee", path, flags, modeFile, 5, 6, base),
			connectEv(210, "evil.example.com", base.Add(time.Second)))
	}
	if f := run(event.OpenWrite); len(f) != 0 {
		t.Fatalf("write-only open flagged: %+v", f)
	}
	if f := run(event.OpenRead | event.OpenWrite); len(f) != 1 {
		t.Fatalf("read-write open: flags = %d, want 1", len(f))
	}
}

func TestOwnerProgramReadsItsCredential(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	hosts := homePath(t, ".config/gh/hosts.yml")
	run := func(exe, path, host string) []model.Flag {
		c := newTwoRootCorrelator(t)
		return flagsFor(c,
			openEv(210, exe, path, event.OpenRead, modeFile, 5, 6, base),
			connectEv(210, host, base.Add(time.Second)))
	}
	if f := run("/opt/homebrew/Cellar/gh/2.102.0/bin/gh", hosts, "20.209.226.1"); len(f) != 0 {
		t.Fatalf("gh reading its token flagged: %+v", f)
	}
	f := run("/usr/bin/curl", hosts, "20.209.226.1")
	if len(f) != 1 || f[0].Severity != 3 {
		t.Fatalf("curl reading the token: flags = %+v, want 1 at severity 3", f)
	}
	for _, exe := range []string{"/usr/local/bin/docker-credential-desktop", "/Applications/Docker.app/Contents/Resources/bin/docker", "/Applications/Docker.app/Contents/MacOS/com.docker.backend"} {
		if f := run(exe, homePath(t, ".docker/config.json"), "evil.example.com"); len(f) != 0 {
			t.Fatalf("%s reading its config flagged: %+v", exe, f)
		}
	}
	if f := run("/usr/bin/curl", homePath(t, ".docker/config.json"), "evil.example.com"); len(f) != 1 {
		t.Fatalf("curl reading docker config: flags = %d, want 1", len(f))
	}
}

func TestAgentToolReadStaysCritical(t *testing.T) {
	c := newTwoRootCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	f := flagsFor(c,
		event.Event{Kind: event.KindPluginAction, PID: 200, ExePath: "/opt/homebrew/bin/gh", Path: homePath(t, ".config/gh/hosts.yml"), TS: base},
		connectEv(210, "20.209.226.1", base.Add(time.Second)))
	if len(f) != 1 || f[0].Severity != 3 {
		t.Fatalf("agent tool read: flags = %+v, want 1 at severity 3", f)
	}
}

func TestOwnDataIsNotACredentialRead(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	env := filepath.Join(t.TempDir(), "TestX", "001", ".env")
	birth := base.UnixNano()
	write := openEv(210, "/tmp/go-build/api.test", env, event.OpenWrite, modeFile, 77, birth, base)
	read := func(pid int32, ino uint64, birth int64) event.Event {
		return openEv(pid, "/tmp/go-build/api.test", env, event.OpenRead, modeFile, ino, birth, base.Add(time.Second))
	}
	conn := func(pid int32) event.Event { return connectEv(pid, "evil.example.com", base.Add(2*time.Second)) }

	c := newTwoRootCorrelator(t)
	if f := flagsFor(c, write, read(210, 77, birth), conn(210)); len(f) != 0 {
		t.Fatalf("read of the tree's own file flagged: %+v", f)
	}
	c = newTwoRootCorrelator(t)
	if f := flagsFor(c, write, read(310, 77, birth), conn(310)); len(f) != 1 {
		t.Fatalf("other root reading the file: flags = %d, want 1", len(f))
	}
	c = newTwoRootCorrelator(t)
	if f := flagsFor(c, write, read(210, 78, birth), conn(210)); len(f) != 1 {
		t.Fatalf("different inode at the path: flags = %d, want 1", len(f))
	}
	c = newTwoRootCorrelator(t)
	if f := flagsFor(c, write, read(210, 77, birth+1), conn(210)); len(f) != 1 {
		t.Fatalf("different birth time at the path: flags = %d, want 1", len(f))
	}
	c = newTwoRootCorrelator(t)
	late := read(210, 77, birth)
	late.TS = base.Add(11 * time.Minute)
	if f := flagsFor(c, write, late, connectEv(210, "evil.example.com", late.TS.Add(time.Second))); len(f) != 1 {
		t.Fatalf("read after the record expired: flags = %d, want 1", len(f))
	}
}

func TestOnlyACreatingOpenMakesOwnData(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	env := filepath.Join(t.TempDir(), "proj", ".env")
	conn := connectEv(210, "evil.example.com", base.Add(2*time.Second))
	read := openEv(210, "/usr/bin/cat", env, event.OpenRead, modeFile, 77, 0, base.Add(time.Second))

	old := base.Add(-30 * 24 * time.Hour).UnixNano()
	c := newTwoRootCorrelator(t)
	read.FileBirth = old
	if f := flagsFor(c, openEv(210, "/usr/bin/tee", env, event.OpenWrite, modeFile, 77, old, base), read, conn); len(f) != 1 {
		t.Fatalf("write-open of a 30-day-old file then read: flags = %d, want 1", len(f))
	}

	born := base.UnixNano()
	read.FileBirth = born
	c = newTwoRootCorrelator(t)
	if f := flagsFor(c, openEv(210, "/usr/bin/tee", env, event.OpenWrite, modeFile, 77, born, base), read, conn); len(f) != 0 {
		t.Fatalf("created then read: flagged %+v", f)
	}

	c = newTwoRootCorrelator(t)
	rw := openEv(210, "/usr/bin/vim", env, event.OpenRead|event.OpenWrite, modeFile, 77, born, base)
	if f := flagsFor(c, rw, connectEv(210, "evil.example.com", base.Add(time.Second))); len(f) != 0 {
		t.Fatalf("creating read-write open seeded a read mark: %+v", f)
	}
}

func TestCredentialOwnerPathIsNeverOwnData(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	hosts := homePath(t, ".config/gh/hosts.yml")
	c := newTwoRootCorrelator(t)
	f := flagsFor(c,
		openEv(210, "/usr/bin/tee", hosts, event.OpenWrite, modeFile, 9, 9, base),
		openEv(210, "/usr/bin/curl", hosts, event.OpenRead, modeFile, 9, 9, base.Add(time.Second)),
		connectEv(210, "evil.example.com", base.Add(2*time.Second)))
	if len(f) != 1 {
		t.Fatalf("rewritten credential read back: flags = %d, want 1", len(f))
	}
	c = newTwoRootCorrelator(t)
	f = flagsFor(c,
		openEv(210, "/usr/bin/tee", hosts, event.OpenWrite, modeFile, 9, 9, base),
		openEv(210, "/opt/homebrew/bin/gh", hosts, event.OpenRead, modeFile, 9, 9, base.Add(time.Second)),
		connectEv(210, "evil.example.com", base.Add(2*time.Second)))
	if len(f) != 0 {
		t.Fatalf("owner program read after a rewrite flagged: %+v", f)
	}
}

func TestStaleReadFlagIDsReclassifiesOwnerProgramReads(t *testing.T) {
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	cl := sensitive.New(cfg)
	hosts := homePath(t, ".config/gh/hosts.yml")
	read := func(exe, sub string) []model.EvidenceItem {
		return []model.EvidenceItem{{Kind: "read", Label: hosts, Rule: "glob:~/.config/gh/hosts.yml", Exe: exe, Sub: sub}, {Kind: "connect", Label: "20.209.226.1:443"}}
	}
	flags := []model.Flag{
		{ID: "gh", Rule: "sensitive-read-then-connect", Evidence: read("/opt/homebrew/Cellar/gh/2.102.0/bin/gh", "sensitive read")},
		{ID: "curl", Rule: "sensitive-read-then-connect", Evidence: read("/usr/bin/curl", "sensitive read")},
		{ID: "tool", Rule: "sensitive-read-then-connect", Evidence: read("/opt/homebrew/bin/gh", "agent tool read")},
		{ID: "no-exe", Rule: "sensitive-read-then-connect", Process: &model.FlagProcess{Exe: "/opt/homebrew/bin/gh"}, Evidence: read("", "sensitive read")},
	}
	got := StaleReadFlagIDs(flags, cl, cfg.CredentialOwners)
	if len(got) != 1 || got[0] != "gh" {
		t.Fatalf("stale ids = %v, want [gh]", got)
	}
}
