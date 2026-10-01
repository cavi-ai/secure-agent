package correlate

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const ghExe = "/opt/homebrew/bin/gh"

func TestModelReadCannotHideBehindNativeCredentialUse(t *testing.T) {
	c := newFamilyCorrelator(t)
	at := time.Unix(1_700_000_000, 0)
	path := homePath(t, ".config/gh/hosts.yml")
	reads := []readMark{
		{path: path, pid: 201, exe: ghExe, kind: event.KindFileOpen, at: at},
		{path: path, pid: 203, kind: event.KindPluginAction, at: at},
	}
	if c.ownerUse(reads, connMark{pid: 201, host: "140.82.114.6", port: 443, at: at.Add(time.Second)}) {
		t.Fatal("model-visible credentials hidden by another process's native read")
	}
}

type githubHelperSource struct{ familyProcSource }

func (githubHelperSource) List() []agents.ProcInfo {
	return append(append([]agents.ProcInfo(nil), familyProcs...),
		agents.ProcInfo{PID: 300, PPID: 200, Exe: "/bin/zsh"},
		agents.ProcInfo{PID: 301, PPID: 300, Exe: ghExe},
		agents.ProcInfo{PID: 302, PPID: 300, Exe: "/usr/bin/git"})
}
func (s githubHelperSource) Info(pid int32) (agents.ProcInfo, bool) {
	for _, p := range s.List() {
		if p.PID == pid {
			return p, true
		}
	}
	return agents.ProcInfo{}, false
}

func TestGitHubSiblingCredentialHelper(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		name, exe, host, path string
		kind                  event.Kind
		gap                   time.Duration
		want                  int
	}{
		{"git helper", "/usr/bin/git", "140.82.114.6", ".config/gh/hosts.yml", event.KindFileOpen, time.Second, 0},
		{"connection first", "/usr/bin/git", "lb-140-82-114-5-iad.github.com", ".config/gh/hosts.yml", event.KindFileOpen, -time.Second, 0},
		{"other executable", "/usr/local/bin/node", "140.82.114.6", ".config/gh/hosts.yml", event.KindFileOpen, time.Second, 1},
		{"shared CDN", "/usr/bin/git", "2606:4700::6812:105d", ".config/gh/hosts.yml", event.KindFileOpen, time.Second, 1},
		{"model visible", "/usr/bin/git", "140.82.114.6", ".config/gh/hosts.yml", event.KindPluginAction, time.Second, 1},
		{"other secret", "/usr/bin/git", "140.82.114.6", ".aws/credentials", event.KindFileOpen, time.Second, 1},
		{"distant connection", "/usr/bin/git", "140.82.114.6", ".config/gh/hosts.yml", event.KindFileOpen, 30 * time.Second, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFamilyCorrelator(t)
			c.tagger = agents.New(c.cfg, githubHelperSource{})
			c.tagger.Refresh()
			read := event.Event{Kind: tc.kind, PID: 301, TS: base, Path: homePath(t, tc.path), ExePath: ghExe}
			conn := event.Event{Kind: event.KindConnOpen, PID: 302, TS: base.Add(tc.gap), RemoteHost: tc.host, RemotePort: 443, ExePath: tc.exe}
			var flags []model.Flag
			if tc.gap < 0 {
				c.Observe(conn)
				flags = c.Observe(read)
			} else {
				c.Observe(read)
				flags = c.Observe(conn)
			}
			if len(flags) != tc.want {
				t.Fatalf("flags=%d want %d", len(flags), tc.want)
			}
			if tc.want == 0 && c.CredentialOwnerUses() != 1 {
				t.Fatal("routine activity was not counted")
			}
		})
	}
}

func ghReads(c *Correlator, t *testing.T, kind event.Kind, at time.Time) []model.Flag {
	return c.Observe(event.Event{Kind: kind, PID: 201, TS: at, Path: homePath(t, ".config/gh/hosts.yml"), ExePath: ghExe})
}

func connectTo(c *Correlator, pid int32, host string, at time.Time) []model.Flag {
	return c.Observe(event.Event{Kind: event.KindConnOpen, PID: pid, TS: at, RemoteHost: host, RemotePort: 443})
}

// gh reading its own token and reaching GitHub is the credential in use:
// counted, never flagged, whichever came first.
func TestCredentialUsedWithItsOwnerIsCounted(t *testing.T) {
	c := newFamilyCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	if f := ghReads(c, t, event.KindFileOpen, base); len(f) != 0 {
		t.Fatalf("read alone flagged: %+v", f)
	}
	for i, host := range []string{"140.82.114.6", "lb-140-82-114-5-iad.github.com"} {
		if f := connectTo(c, 201, host, base.Add(time.Duration(i+1)*time.Second)); len(f) != 0 {
			t.Fatalf("gh → %s flagged: %+v", host, f)
		}
	}
	later := base.Add(10 * time.Minute)
	connectTo(c, 201, "140.82.114.6", later)
	if f := ghReads(c, t, event.KindFileOpen, later.Add(2*time.Second)); len(f) != 0 {
		t.Fatalf("connect first, then owner read flagged: %+v", f)
	}
	if got := c.CredentialOwnerUses(); got != 3 {
		t.Fatalf("owner uses = %d, want 3", got)
	}
}

// Other processes reading the same file do not matter when the connecting
// process read it too; without its own read, the connection still flags.
func TestSiblingReadsOfTheSameFile(t *testing.T) {
	c := newFamilyCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	hosts := homePath(t, ".config/gh/hosts.yml")
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 203, TS: base, Path: hosts, ExePath: ghExe})
	ghReads(c, t, event.KindFileOpen, base.Add(time.Second))
	if f := connectTo(c, 201, "140.82.112.5", base.Add(2*time.Second)); len(f) != 0 {
		t.Fatalf("gh reached GitHub after reading the file itself, flagged: %+v", f)
	}
	c = newFamilyCorrelator(t)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 203, TS: base, Path: hosts, ExePath: ghExe})
	if f := connectTo(c, 201, "140.82.112.5", base.Add(2*time.Second)); len(f) != 1 {
		t.Fatalf("connection without its own read: flags = %+v, want 1", f)
	}
}

// The token may reach its owner through the reader's tree: git-remote-https
// running gh as its credential helper, or the agent above gh.
func TestCredentialOwnerThroughTheReadersTree(t *testing.T) {
	for _, pid := range []int32{202, 200} {
		c := newFamilyCorrelator(t)
		base := time.Unix(1_700_000_000, 0)
		ghReads(c, t, event.KindFileOpen, base)
		if f := connectTo(c, pid, "140.82.112.3", base.Add(time.Second)); len(f) != 0 {
			t.Fatalf("pid %d → GitHub flagged: %+v", pid, f)
		}
		if c.CredentialOwnerUses() != 1 {
			t.Fatalf("pid %d: owner uses = %d, want 1", pid, c.CredentialOwnerUses())
		}
	}
}

// The owner check needs the reader's own process tree, a file open (not an
// agent tool read), and an org that owns the credential.
func TestCredentialOutsideItsOwnerFlags(t *testing.T) {
	cases := []struct {
		name string
		kind event.Kind
		pid  int32
		host string
	}{
		{"other org", event.KindFileOpen, 201, "2606:4700::6812:105d"},
		{"process outside the reader's tree", event.KindFileOpen, 203, "140.82.114.6"},
		{"agent tool read", event.KindPluginAction, 201, "140.82.114.6"},
	}
	for _, tc := range cases {
		c := newFamilyCorrelator(t)
		base := time.Unix(1_700_000_000, 0)
		ghReads(c, t, tc.kind, base)
		f := connectTo(c, tc.pid, tc.host, base.Add(2*time.Second))
		if len(f) != 1 || f[0].Rule != readConnectRule {
			t.Fatalf("%s: flags = %+v, want 1 read-then-connect", tc.name, f)
		}
		if conn := f[0].Evidence[len(f[0].Evidence)-1]; conn.Kind != "connect" || conn.PID != tc.pid {
			t.Fatalf("%s: connect evidence = %+v, want pid %d", tc.name, conn, tc.pid)
		}
		if c.CredentialOwnerUses() != 0 {
			t.Fatalf("%s: counted as owner use", tc.name)
		}
		read := f[0].Evidence[0]
		wantSub := "sensitive read"
		if tc.kind == event.KindPluginAction {
			wantSub = "agent tool read"
		}
		if len(read.Owners) != 1 || read.Owners[0] != "GitHub" || read.Sub != wantSub {
			t.Fatalf("%s: read evidence owners/sub = %v/%q, want [GitHub]/%q", tc.name, read.Owners, read.Sub, wantSub)
		}
	}
}

// When one connection is the owner and another is not, the flag cites only
// the other.
func TestOwnerConnectionIsNotCited(t *testing.T) {
	c := newFamilyCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	connectTo(c, 201, "140.82.114.6", base)
	connectTo(c, 201, "evil.example.com", base.Add(time.Second))
	f := ghReads(c, t, event.KindFileOpen, base.Add(2*time.Second))
	if len(f) != 1 {
		t.Fatalf("flags = %+v, want 1", f)
	}
	var cited []string
	for _, ev := range f[0].Evidence {
		if ev.Kind == "connect" {
			cited = append(cited, ev.Label)
		}
	}
	if len(cited) != 1 || cited[0] != "evil.example.com:443" {
		t.Fatalf("cited = %v, want only evil.example.com:443", cited)
	}
}

// One pattern (agent, reader, secret, destination org) is one flag per
// hour; repeats fold into it. A new destination or a new window flags again.
func TestReadThenConnectRepeatsFold(t *testing.T) {
	c := newFamilyCorrelator(t)
	type rep struct {
		id string
		at time.Time
	}
	var reps []rep
	c.SetOnRepeat(func(id string, at time.Time) { reps = append(reps, rep{id, at}) })
	base := time.Unix(1_700_000_000, 0)
	aws := homePath(t, ".aws/credentials")
	var raised []model.Flag
	for i := 0; i < 23; i++ {
		at := base.Add(time.Duration(i) * 53 * time.Second)
		c.Observe(event.Event{Kind: event.KindFileOpen, PID: 201, TS: at, Path: aws, ExePath: ghExe})
		raised = append(raised, connectTo(c, 201, "evil.example.com", at.Add(time.Second))...)
	}
	if len(raised) != 1 || len(reps) != 22 {
		t.Fatalf("raised %d flags, %d repeats; want 1 and 22", len(raised), len(reps))
	}
	for _, r := range reps {
		if r.id != raised[0].ID {
			t.Fatalf("repeat folded into %s, want %s", r.id, raised[0].ID)
		}
	}
	at := base.Add(25 * time.Minute)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 201, TS: at, Path: aws, ExePath: ghExe})
	if f := connectTo(c, 201, "other.example.net", at.Add(time.Second)); len(f) != 1 {
		t.Fatalf("new destination: flags = %+v, want 1", f)
	}
	at = base.Add(61 * time.Minute)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 201, TS: at, Path: aws, ExePath: ghExe})
	if f := connectTo(c, 201, "evil.example.com", at.Add(time.Second)); len(f) != 1 || f[0].ID == raised[0].ID {
		t.Fatalf("next window: flags = %+v, want 1 new flag", f)
	}
}

func TestReadThenConnectNewFileDoesNotFoldIntoOldPattern(t *testing.T) {
	c := newFamilyCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	aws := homePath(t, ".aws/credentials")
	gh := homePath(t, ".config/gh/hosts.yml")
	read := func(path string, at time.Time) {
		c.Observe(event.Event{Kind: event.KindFileOpen, PID: 201, TS: at, Path: path, ExePath: ghExe})
	}
	read(aws, base)
	first := connectTo(c, 201, "evil.example.com", base.Add(time.Second))
	if len(first) != 1 {
		t.Fatalf("first connection: flags = %+v, want 1", first)
	}
	read(aws, base.Add(2*time.Minute))
	read(gh, base.Add(2*time.Minute+time.Second))
	second := connectTo(c, 201, "evil.example.com", base.Add(2*time.Minute+2*time.Second))
	if len(second) != 1 || second[0].ID == first[0].ID {
		t.Fatalf("newly read credential must raise a new flag, got %+v", second)
	}
}

func TestEnvTemplateIsNotAStaleSecret(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: "/Users/x/proj/.env.example"})
	if f := connect(c, 200, base.Add(2*time.Second)); len(f) != 0 {
		t.Fatalf(".env.example read then connect flagged: %+v", f)
	}
	flags := []model.Flag{
		{ID: "tmpl", Rule: readConnectRule, Evidence: []model.EvidenceItem{{Kind: "read", Label: "/Users/x/proj/.env.example", Rule: "env-file"}}},
		{ID: "real", Rule: readConnectRule, Evidence: []model.EvidenceItem{{Kind: "read", Label: "/Users/x/proj/.env.local", Rule: "env-file"}}},
	}
	if got := StaleReadFlagIDs(flags, c.classifier); len(got) != 1 || got[0] != "tmpl" {
		t.Fatalf("stale = %v, want [tmpl]", got)
	}
}

// zsh completions under ~/.docker are read at every shell start: not a
// secret, live or stored; ~/.docker/config.json still is.
func TestNotSecretPathUnderSensitiveDir(t *testing.T) {
	c := newTestCorrelator(t)
	base := time.Unix(1_700_000_000, 0)
	completion := homePath(t, ".docker/completions/_docker")
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: completion})
	if f := connect(c, 200, base.Add(2*time.Second)); len(f) != 0 {
		t.Fatalf("completion read then connect flagged: %+v", f)
	}
	docker := homePath(t, ".docker")
	flags := []model.Flag{
		{ID: "completion", Rule: readConnectRule, Evidence: []model.EvidenceItem{{Kind: "read", Label: completion, Rule: "path:" + docker}}},
		{ID: "config", Rule: readConnectRule, Evidence: []model.EvidenceItem{{Kind: "read", Label: homePath(t, ".docker/config.json"), Rule: "path:" + docker}}},
	}
	if got := StaleReadFlagIDs(flags, c.classifier); len(got) != 1 || got[0] != "completion" {
		t.Fatalf("stale = %v, want [completion]", got)
	}
}

func TestReadConnectOpenFindingDoesNotRealertHourly(t *testing.T) {
	c := newFamilyCorrelator(t)
	base := time.Unix(1700000000, 0)
	var first string
	open := true
	c.SetOpenFlagChecker(func(id string) bool { return id == first && open })
	for _, minutes := range []int{0, 61, 125} {
		at := base.Add(time.Duration(minutes) * time.Minute)
		ghReads(c, t, event.KindFileOpen, at)
		flags := connectTo(c, 201, "evil.example.com", at.Add(time.Second))
		if minutes == 0 {
			if len(flags) != 1 {
				t.Fatal(flags)
			}
			first = flags[0].ID
		} else if len(flags) != 0 {
			t.Fatalf("unresolved finding re-alerted at %d minutes", minutes)
		}
	}
	open = false
	at := base.Add(130 * time.Minute)
	ghReads(c, t, event.KindFileOpen, at)
	if f := connectTo(c, 201, "evil.example.com", at.Add(time.Second)); len(f) != 1 {
		t.Fatal("new occurrence after dismissal must still flag")
	}
}
func TestReadConnectRepeatEscalatesStrongerEvidence(t *testing.T) {
	c := newFamilyCorrelator(t)
	at := time.Unix(1700000000, 0)
	ghReads(c, t, event.KindFileOpen, at)
	f := connectTo(c, 200, "evil.example.com", at.Add(time.Second))
	if len(f) != 1 || f[0].Severity != 2 {
		t.Fatal(f)
	}
	ghReads(c, t, event.KindFileOpen, at.Add(2*time.Minute))
	f = connectTo(c, 201, "evil.example.com", at.Add(2*time.Minute+time.Second))
	if len(f) != 1 || f[0].Severity != 3 {
		t.Fatal("stronger direct evidence was folded into weak correlation", f)
	}
}

func TestOpenReadFindingFoldingSurvivesRestart(t *testing.T) {
	c := newFamilyCorrelator(t)
	at := time.Unix(1700000000, 0)
	path := homePath(t, ".config/gh/hosts.yml")
	c.RestoreOpenReadFlags([]model.Flag{{ID: "retained", Rule: readConnectRule, Severity: 3, TS: at, Agent: "cursor", Evidence: []model.EvidenceItem{{Kind: "read", Label: path, Exe: ghExe}, {Kind: "connect", Label: "evil.example.com:443"}}}})
	c.SetOpenFlagChecker(func(id string) bool { return id == "retained" })
	ghReads(c, t, event.KindFileOpen, at.Add(2*time.Hour))
	if f := connectTo(c, 201, "evil.example.com", at.Add(2*time.Hour+time.Second)); len(f) != 0 {
		t.Fatal("restart duplicated unresolved finding", f)
	}
}
