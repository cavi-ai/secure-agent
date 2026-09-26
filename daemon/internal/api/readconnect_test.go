package api

import (
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const ghHosts = "/Users/dev/.config/gh/hosts.yml"

func ghFlag(id string, ts time.Time, read model.EvidenceItem, host string) model.Flag {
	return model.Flag{ID: id, Rule: readConnectRule, Severity: 3, TS: ts, PID: 900, Agent: "claude", SessionID: "s1",
		Evidence: []model.EvidenceItem{read, {Kind: "connect", Label: host + ":443", Sub: "egress", PID: 900}}}
}

func ghRead(sub string, pid int32, owners ...string) model.EvidenceItem {
	return model.EvidenceItem{Kind: "read", Label: ghHosts, Sub: sub, Rule: "glob:" + ghHosts, PID: pid, Exe: "/opt/homebrew/bin/gh", Owners: owners}
}

// The verdict line says why the flag needs a look, from its evidence.
func TestReadConnectWhy(t *testing.T) {
	pinExplainHome(t, "/Users/dev")
	now := time.Now()
	cases := []struct {
		name string
		f    model.Flag
		want string
	}{
		{"other org", ghFlag("a", now, ghRead("sensitive read", 900, "GitHub"), "2606:4700::6812:105d"),
			"Cloudflare does not own ~/.config/gh/hosts.yml (owner: GitHub)."},
		{"unknown host", ghFlag("b", now, ghRead("sensitive read", 900, "GitHub"), "evil.example.com"),
			"evil.example.com does not own ~/.config/gh/hosts.yml (owner: GitHub)."},
		{"no owner on record", ghFlag("c", now, ghRead("sensitive read", 900), "140.82.114.6"),
			"No owner is on record for ~/.config/gh/hosts.yml; the connection went to GitHub."},
		{"tool read", ghFlag("d", now, ghRead("agent tool read", 900, "GitHub"), "140.82.114.6"),
			"GitHub owns ~/.config/gh/hosts.yml, but an agent tool read it into the model's context."},
		{"other process", ghFlag("e", now, ghRead("sensitive read", 901, "GitHub"), "140.82.114.6"),
			"GitHub owns ~/.config/gh/hosts.yml, but a process outside the reader's process tree made the connection."},
		{"legacy evidence", ghFlag("f", now, ghRead("sensitive read", 0), "140.82.114.6"),
			"Agent read a secret, then connected out"},
	}
	for _, tc := range cases {
		d := dispositionFor(tc.f)
		if d.State != model.DispositionCritical || d.Why != tc.want {
			t.Errorf("%s: disposition = %s %q, want critical %q", tc.name, d.State, d.Why, tc.want)
		}
	}
}

// The pattern card names the reader, the file and where it went; Count
// includes folded repeats while Flags counts flags.
func TestReadConnectPatternSummary(t *testing.T) {
	pinExplainHome(t, "/Users/dev")
	a := explainTestAPI(t)
	start := time.Now().Add(-20 * time.Minute)
	for i, host := range []string{"lb-140-82-114-5-iad.github.com", "lcmiaa-al-in-x0e.1e100.net", "lcmiaa-an-in-x0e.1e100.net"} {
		a.store.PutFlag(ghFlag(string(rune('a'+i)), start.Add(time.Duration(i)*time.Minute), ghRead("sensitive read", 901, "GitHub"), host))
	}
	a.store.BumpFlagRepeat("c", start.Add(5*time.Minute))
	p := onlyPattern(t, a.computePatterns(time.Now().Add(-24*time.Hour), 3))
	if p.Count != 4 || p.Flags != 3 {
		t.Fatalf("count/flags = %d/%d, want 4/3", p.Count, p.Flags)
	}
	if len(p.Destinations) != 2 || p.Destinations[0].Org != "Google" || p.Destinations[0].Count != 2 || p.Destinations[1].Org != "GitHub" {
		t.Fatalf("destinations = %+v, want Google ×2 then GitHub", p.Destinations)
	}
	want := "gh (claude) read ~/.config/gh/hosts.yml, then reached Google (lcmiaa-al-in-x0e.1e100.net) and 1 more destination 4 times "
	if !strings.HasPrefix(p.Summary, want) {
		t.Fatalf("summary = %q, want prefix %q", p.Summary, want)
	}
	// The newest open flag (Google) carries the pattern's verdict.
	if want := "Google does not own ~/.config/gh/hosts.yml (owner: GitHub)."; p.Disposition.Why != want {
		t.Fatalf("pattern why = %q, want %q", p.Disposition.Why, want)
	}
}

// The explanation sentence names the reader when it is not the agent.
func TestExplainWhatNamesTheReader(t *testing.T) {
	pinExplainHome(t, "/Users/dev")
	a := explainTestAPI(t)
	f := ghFlag("g", time.Now(), ghRead("sensitive read", 901, "GitHub"), "140.82.114.6")
	a.store.PutFlag(f)
	ex := a.explainFlag(f, false)
	if !strings.HasPrefix(ex.What, "gh (Claude) read ") || !strings.Contains(ex.What, "then reached GitHub") {
		t.Fatalf("what = %q, want the reader gh named and GitHub reached", ex.What)
	}
	self := ghRead("sensitive read", 900, "GitHub")
	self.Exe = "/Users/dev/.local/share/claude/versions/2.1.281"
	if ex := a.explainFlag(ghFlag("h", time.Now(), self, "140.82.114.6"), false); strings.Contains(ex.What, "(Claude)") {
		t.Fatalf("what = %q, the agent itself must not be named twice", ex.What)
	}
}
