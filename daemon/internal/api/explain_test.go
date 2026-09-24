package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata golden files")

// pinExplainHome fixes the home directory the owner labels resolve against,
// so labels and goldens do not depend on the machine running the test.
func pinExplainHome(t *testing.T, home string) {
	t.Helper()
	orig := explainHome
	explainHome = func() string { return home }
	t.Cleanup(func() { explainHome = orig })
}

func explainTestAPI(t *testing.T, agents ...AgentSummary) *API {
	t.Helper()
	a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status { return Status{Running: true, Agents: agents} })
	dir := t.TempDir()
	a.allowlist = correlate.NewAllowlistStore(filepath.Join(dir, "allowlist.json"))
	a.mutes = correlate.NewMuteStore(filepath.Join(dir, "mutes.json"))
	a.guardBroker = guard.NewBroker(time.Minute)
	return a
}

const liveFixturePath = "/Users/dev/.claude/skills/synced/00000000-0000-4000-8000-000000000001_00000000-0000-4000-8000-000000000002/example-skill/config"

// liveFixtureFlag is flag 12e7022e2de04005 as stored by the live daemon on
// 2026-09-23 (evidence copied from the store).
func liveFixtureFlag() model.Flag {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-09-23T00:01:33.112461172Z")
	conn := func(label, at string) model.EvidenceItem {
		return model.EvidenceItem{Kind: "connect", Label: label, Sub: "egress", TS: at, Text: "then connected to " + label + " at " + at}
	}
	return model.Flag{
		ID: "12e7022e2de04005", Rule: "sensitive-read-then-connect", Severity: 3, TS: ts, PID: 13250, Agent: "claude",
		Evidence: []model.EvidenceItem{
			{Kind: "read", Label: liveFixturePath, Sub: "sensitive read", TS: "2026-09-23T00:01:33Z",
				Text: "claude (pid 13250) read " + liveFixturePath + " at 2026-09-23T00:01:33Z"},
			conn("2600:1f10:4fa9:a02:3441:aad6:bb1a:fd73:443", "2026-09-22T20:01:36-04:00"),
			conn("2606:4700:20::681a:4a4:443", "2026-09-22T20:01:38-04:00"),
			conn("2606:4700:20::681a:4a4:443", "2026-09-22T20:01:42-04:00"),
		},
	}
}

func liveFixtureVerdict() model.AdvisorVerdict {
	return model.AdvisorVerdict{
		Assessment: "benign", Confidence: 0.93,
		Rationale:       "The Claude agent read its own example-skill skill config under ~/.claude/skills/synced/ and then made HTTPS connections to Cloudflare (2600:1f10:4fa9 / 2606:4700:20::), which is a standard API/CDN endpoint, not an exfiltration target.",
		SuggestedAction: "allow-host",
		CreatedAt:       time.Date(2026, 9, 23, 0, 2, 0, 0, time.UTC),
	}
}

// 1. One disposition, in precedence order.
func TestDispositionPrecedence(t *testing.T) {
	benign := func(c float64) *model.AdvisorVerdict {
		return &model.AdvisorVerdict{Assessment: "benign", Confidence: c, Rationale: "It read its own config. Nothing left the machine."}
	}
	cases := []struct {
		name        string
		f           model.Flag
		state, text string
		why         string
	}{
		{"acknowledged beats benign", model.Flag{Rule: "tcc-tamper", Severity: 3, Acknowledged: true, Advisor: benign(0.93)}, "acknowledged", "Reviewed", "Agent modified macOS privacy permissions (TCC)"},
		{"benign 0.93 sev 3", model.Flag{Severity: 3, Advisor: benign(0.93)}, "benign-likely", "Likely benign (advisor 93 %)", "It read its own config."},
		{"benign 0.60 sev 3", model.Flag{Rule: "sensitive-read-then-connect", Severity: 3, Advisor: benign(0.60)}, "critical", "Act now", "Agent read a secret, then connected out"},
		{"suspicious sev 2", model.Flag{Rule: "keychain-access", Severity: 2, Advisor: &model.AdvisorVerdict{Assessment: "suspicious", Confidence: 0.9}}, "warning", "Needs a look", "Agent touched the keychain"},
		{"nil advisor sev 3", model.Flag{Rule: "proxy-secret-leak", Severity: 3}, "critical", "Act now", "Secret leaving in agent traffic"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := dispositionFor(c.f)
			if d.State != c.state || d.Text != c.text || d.Why != c.why {
				t.Fatalf("dispositionFor = %+v, want state %q text %q why %q", d, c.state, c.text, c.why)
			}
		})
	}
}

func readFlag(path, rule, sessionID string) model.Flag {
	return model.Flag{
		ID: "f-" + filepath.Base(path), Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), Agent: "claude", SessionID: sessionID,
		Evidence: []model.EvidenceItem{{Kind: "read", Label: path, Sub: "sensitive read", Rule: rule, TS: time.Now().UTC().Format(time.RFC3339)}},
	}
}

// 3. Category and owner labels.
func TestExplainSubjectCategoryAndOwner(t *testing.T) {
	home := "/Users/tester"
	pinExplainHome(t, home)
	a := explainTestAPI(t)
	ws := home + "/work/api"
	a.store.UpsertSession(model.Session{ID: "s1", Harness: "claude", Workspace: ws, Repo: "api", Branch: "main", StartedAt: time.Now(), LastSeenAt: time.Now(), Status: model.SessionActive, Confidence: model.ConfHook})
	cases := []struct {
		path, rule, cat, label, owner string
	}{
		{home + "/.aws/credentials", "aws", "aws_credentials", "AWS credentials", "home directory"},
		{home + "/.ssh/id_ed25519", "ssh-key", "ssh_key", "SSH private key", "home directory"},
		{ws + "/.env", "env-file", "env_file", "environment file", "repo api"},
		{home + "/.claude/skills/x/config", "glob:~/.claude/skills/**", "other_sensitive", "sensitive file", "Claude skills (~/.claude/skills)"},
		{"/var/folders/xy/abc123/T/tmp.1/.env", "env-file", "env_file", "environment file", "temp directory"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			ex := a.explainFlag(readFlag(c.path, c.rule, "s1"), false)
			s := ex.Subject
			if s == nil {
				t.Fatal("subject missing")
			}
			if s.Path != c.path || s.Basename != filepath.Base(c.path) || s.Rule != c.rule {
				t.Fatalf("subject = %+v", s)
			}
			if s.Category != c.cat || s.CategoryLabel != c.label || s.OwnerLabel != c.owner {
				t.Fatalf("category/label/owner = %q/%q/%q, want %q/%q/%q", s.Category, s.CategoryLabel, s.OwnerLabel, c.cat, c.label, c.owner)
			}
			if n := len([]rune(s.Display)); n > 64 {
				t.Fatalf("display %q is %d runes, want <= 64", s.Display, n)
			}
		})
	}
}

// 4. One sentence per rule: no pids, the org instead of a raw IP.
func TestExplainWhatPerRule(t *testing.T) {
	home := "/Users/tester"
	pinExplainHome(t, home)
	a := explainTestAPI(t)
	ws := home + "/work/api"
	a.store.UpsertSession(model.Session{ID: "s1", Harness: "claude", Workspace: ws, Repo: "api", StartedAt: time.Now(), LastSeenAt: time.Now(), Status: model.SessionActive, Confidence: model.ConfHook})
	t0 := time.Date(2026, 9, 23, 0, 1, 33, 0, time.UTC)
	at := func(d time.Duration) string { return t0.Add(d).Format(time.RFC3339) }
	cf := "2606:4700:20::681a:4a4:443"
	cases := []struct {
		rule string
		ev   []model.EvidenceItem
		want string
	}{
		{"sensitive-read-then-connect", []model.EvidenceItem{
			{Kind: "read", Label: ws + "/.env", Rule: "env-file", TS: at(0)},
			{Kind: "connect", Label: cf, TS: at(3 * time.Second)},
		}, "Claude read an environment file in repo api, then reached Cloudflare 3 s later."},
		{"keychain-access", []model.EvidenceItem{
			{Kind: "keychain", Label: home + "/Library/Keychains/login.keychain-db", TS: at(0)},
		}, "Claude opened login.keychain-db in the keychain."},
		{"keychain-security-cli", []model.EvidenceItem{
			{Kind: "exec", Label: "/usr/bin/security", Sub: "keychain CLI", TS: at(0)},
		}, "Claude ran the keychain tool."},
		{"tcc-tamper", []model.EvidenceItem{
			{Kind: "tcc", Label: "kTCCServiceAccessibility", TS: at(0)},
		}, "Claude changed macOS privacy permissions (kTCCServiceAccessibility)."},
		{"proxy-secret-leak", []model.EvidenceItem{
			{Kind: "violation", Label: "proxy-secret-leak:aws-key", Sub: "payload inspection"},
			{Kind: "connect", Label: cf, Sub: "destination"},
		}, "Claude sent a secret (aws-key) to Cloudflare."},
		{"proxy-prompt-injection", []model.EvidenceItem{
			{Kind: "violation", Label: "proxy-prompt-injection:ignore-previous", Sub: "payload inspection"},
			{Kind: "connect", Label: "api.example.com:443", Sub: "destination"},
		}, "A response to Claude from api.example.com contained a prompt injection."},
		{"secret-in-transcript", []model.EvidenceItem{
			{Kind: "transcript", Label: home + "/.claude/projects/p/abc.jsonl", Sub: "pattern match", Rule: "aws-access-key", TS: at(0)},
		}, "A secret (aws-access-key) appeared in a Claude transcript (abc.jsonl)."},
		{"proxy-payload-inspection", []model.EvidenceItem{
			{Kind: "violation", Label: "proxy-scan", Sub: "payload inspection"},
		}, "proxy-payload-inspection"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			f := model.Flag{ID: "w-" + c.rule, Rule: c.rule, Severity: 3, TS: t0, PID: 4242, Agent: "claude", SessionID: "s1", Evidence: c.ev}
			ex := a.explainFlag(f, false)
			if ex.What != c.want {
				t.Fatalf("what = %q, want %q", ex.What, c.want)
			}
			if strings.Contains(strings.ToLower(ex.What), "pid") || strings.Contains(ex.What, "4242") {
				t.Fatalf("what %q leaks a pid", ex.What)
			}
		})
	}
}

// 5. Egress: dedupe by host:port, gap from the live fixture, allowlist state.
func TestExplainEgress(t *testing.T) {
	pinExplainHome(t, "/Users/dev")
	a := explainTestAPI(t)
	f := liveFixtureFlag()
	ex := a.explainFlag(f, false)
	if len(ex.Egress) != 2 {
		t.Fatalf("egress = %+v, want 2 (the repeated Cloudflare host:port deduped)", ex.Egress)
	}
	aws, cf := ex.Egress[0], ex.Egress[1]
	if aws.Host != "2600:1f10:4fa9:a02:3441:aad6:bb1a:fd73" || aws.Port != 443 || aws.Org != "AWS" || aws.Kind != "ipv6" || aws.GapSeconds != 3 {
		t.Fatalf("first egress = %+v, want AWS :443 gap 3", aws)
	}
	if cf.Host != "2606:4700:20::681a:4a4" || cf.Org != "Cloudflare" || cf.GapSeconds != 5 {
		t.Fatalf("second egress = %+v, want Cloudflare gap 5", cf)
	}
	if aws.Allowlisted || cf.Allowlisted {
		t.Fatal("nothing is allowlisted yet")
	}
	if err := a.allowlist.Add("claude", "2606:4700:20::681a:4a4"); err != nil {
		t.Fatal(err)
	}
	ex = a.explainFlag(f, false)
	if ex.Egress[0].Allowlisted || !ex.Egress[1].Allowlisted {
		t.Fatalf("after allowlisting the Cloudflare host: %+v", ex.Egress)
	}
	// Suffix rule shared with the correlator: example.com covers api.example.com.
	if err := a.allowlist.Add("claude", "example.com"); err != nil {
		t.Fatal(err)
	}
	g := model.Flag{ID: "g", Rule: "proxy-secret-leak", Severity: 3, Agent: "claude", Evidence: []model.EvidenceItem{
		{Kind: "connect", Label: "api.example.com:443"}, {Kind: "connect", Label: "api.example.com:8443"},
	}}
	ex = a.explainFlag(g, false)
	if len(ex.Egress) != 2 || !ex.Egress[0].Allowlisted || ex.Egress[0].GapSeconds != 0 {
		t.Fatalf("egress = %+v, want two ports, suffix-allowlisted, gap 0 without a read", ex.Egress)
	}
}

func putToolCall(a *API, session, tool, status, callID string, ts time.Time) {
	a.store.PutEvent(event.Event{Kind: event.KindToolCall, TS: ts, SessionID: session, ToolName: tool, ToolStatus: status, CallID: callID})
}

// 6. Context: the session, the tool call nearest the read, the model.
func TestExplainContext(t *testing.T) {
	pinExplainHome(t, "/Users/tester")
	a := explainTestAPI(t)
	a.store.UpsertSession(model.Session{ID: "s1", Harness: "claude", Workspace: "/Users/tester/work/api", Repo: "api", Branch: "main", StartedAt: time.Now(), LastSeenAt: time.Now(), Status: model.SessionActive, Confidence: model.ConfHook})
	read := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	putToolCall(a, "s1", "Bash", "ok", "c-far", read.Add(30*time.Second))
	putToolCall(a, "s1", "Read", "ok", "c-near", read.Add(2*time.Second))
	putToolCall(a, "s2", "Other", "ok", "c-other", read.Add(1*time.Second))
	a.store.PutEvent(event.Event{Kind: event.KindModelCall, TS: read.Add(-20 * time.Second), SessionID: "s1", Model: "claude-opus-5-5"})
	f := readFlag("/Users/tester/work/api/.env", "env-file", "s1")
	f.Evidence[0].TS = read.Format(time.RFC3339)
	ex := a.explainFlag(f, false)
	c := ex.Context
	if c == nil {
		t.Fatal("context missing")
	}
	if c.SessionID != "s1" || c.Harness != "claude" || c.Repo != "api" || c.Branch != "main" || c.Workspace != "/Users/tester/work/api" {
		t.Fatalf("session fields = %+v", c)
	}
	if c.Tool != "Read" || c.ToolStatus != "ok" || c.ToolAt == nil || !c.ToolAt.Equal(read.Add(2*time.Second)) {
		t.Fatalf("tool = %q/%q at %v, want the nearest same-session call (Read)", c.Tool, c.ToolStatus, c.ToolAt)
	}
	if c.Model != "claude-opus-5-5" {
		t.Fatalf("model = %q", c.Model)
	}

	// No tool call within ±60 s: empty tool, no model.
	b := explainTestAPI(t)
	b.store.UpsertSession(model.Session{ID: "s1", Harness: "claude", StartedAt: time.Now(), LastSeenAt: time.Now(), Status: model.SessionActive, Confidence: model.ConfHook})
	putToolCall(b, "s1", "Bash", "ok", "c-late", read.Add(90*time.Second))
	ex = b.explainFlag(f, false)
	if ex.Context == nil || ex.Context.Tool != "" || ex.Context.ToolAt != nil || ex.Context.Model != "" {
		t.Fatalf("context = %+v, want no tool and no model", ex.Context)
	}
}

func actionIDs(ex *model.FlagExplain) []string {
	out := []string{}
	for _, act := range ex.Actions {
		out = append(out, act.ID)
	}
	return out
}

func recommendedID(ex *model.FlagExplain) string {
	for _, act := range ex.Actions {
		if act.Recommended {
			return act.ID
		}
	}
	return ""
}

// Served mute actions carry the flag's agent in the body and name it in the
// label; an agent-less flag keeps the every-agent mute.
func TestExplainMuteActionsCarryAgent(t *testing.T) {
	home := "/Users/tester"
	pinExplainHome(t, home)
	a := explainTestAPI(t)
	kc := a.explainFlag(model.Flag{ID: "k1", Rule: "keychain-access", Severity: 1, PID: 999, Agent: "codex",
		Evidence: []model.EvidenceItem{{Kind: "keychain", Label: home + "/Library/Keychains/login.keychain-db"}}}, false)
	mute := actionByID(kc.Actions, "mute-class")
	if mute == nil || mute.Label != "Mute keychain access for codex" || mute.Body["agent"] != "codex" || mute.Body["host"] != "*" {
		t.Fatalf("mute-class = %+v", mute)
	}
	eg := a.explainFlag(model.Flag{ID: "p1", Rule: "proxy-secret-leak", Severity: 3, Agent: "claude",
		Evidence: []model.EvidenceItem{{Kind: "violation", Label: "proxy-secret-leak:aws-key"}, {Kind: "connect", Label: "api.example.com:443"}}}, false)
	host := actionByID(eg.Actions, "mute-rule-host")
	if host == nil || host.Label != "Stop flagging this for api.example.com from claude" || host.Body["agent"] != "claude" || host.Body["host"] != "api.example.com" {
		t.Fatalf("mute-rule-host = %+v", host)
	}
	anon := a.explainFlag(model.Flag{ID: "k2", Rule: "keychain-access", Severity: 1, PID: 999,
		Evidence: []model.EvidenceItem{{Kind: "keychain", Label: home + "/Library/Keychains/login.keychain-db"}}}, false)
	if m := actionByID(anon.Actions, "mute-class"); m == nil || m.Label != "Dismiss this flag class" || m.Body["agent"] != nil {
		t.Fatalf("agent-less mute-class = %+v", m)
	}
}

func TestExplainOmitsMuteForUnscopableAgent(t *testing.T) {
	home := "/Users/tester"
	pinExplainHome(t, home)
	a := explainTestAPI(t)
	const agent = "team/bot"
	flags := []model.Flag{
		{ID: "k1", Rule: "keychain-access", Severity: 1, PID: 999, Agent: agent,
			Evidence: []model.EvidenceItem{{Kind: "keychain", Label: home + "/Library/Keychains/login.keychain-db"}}},
		{ID: "p1", Rule: "proxy-secret-leak", Severity: 3, Agent: agent,
			Evidence: []model.EvidenceItem{{Kind: "violation", Label: "proxy-secret-leak:aws-key"}, {Kind: "connect", Label: "api.example.com:443"}}},
	}
	for _, f := range flags {
		for _, act := range a.explainFlag(f, false).Actions {
			if act.Path == "/mute" {
				t.Fatalf("%s: agent %q cannot scope a mute, yet %s was served with body %v", f.Rule, agent, act.ID, act.Body)
			}
		}
	}
}

// 7. Actions per rule, in order, only those that apply.
func TestExplainActions(t *testing.T) {
	home := "/Users/tester"
	pinExplainHome(t, home)
	a := explainTestAPI(t, AgentSummary{PID: 4242, Name: "claude", StartedAt: "2026-09-23T00:00:00Z"})
	a.store.UpsertSession(model.Session{ID: "s1", Harness: "claude", Workspace: home + "/work/api", Repo: "api", StartedAt: time.Now(), LastSeenAt: time.Now(), Status: model.SessionActive, Confidence: model.ConfHook})
	a.store.PutIncident(model.IncidentReport{ID: "inc-1", FlagID: "with-incident", Rule: "sensitive-read-then-connect", Timestamp: time.Now()})
	envRead := model.EvidenceItem{Kind: "read", Label: home + "/work/api/.env", Rule: "env-file", TS: time.Now().UTC().Format(time.RFC3339)}
	conn := func(h string) model.EvidenceItem { return model.EvidenceItem{Kind: "connect", Label: h} }
	adv := func(action string) *model.AdvisorVerdict {
		return &model.AdvisorVerdict{Assessment: "suspicious", Confidence: 0.7, SuggestedAction: action}
	}
	cases := []struct {
		name string
		f    model.Flag
		ids  []string
		rec  string
	}{
		{"read-then-connect, live pid, incident, advisor allow-host",
			model.Flag{ID: "with-incident", Rule: "sensitive-read-then-connect", Severity: 3, PID: 4242, Agent: "claude", SessionID: "s1",
				Evidence: []model.EvidenceItem{envRead, conn("api.example.com:443"), conn("cdn.example.net:443")}, Advisor: adv("allow-host")},
			[]string{"allow-host", "allow-host", "allow-path", "mute-rule-host", "open-incident", "dismiss", "kill"}, "allow-host"},
		{"read-then-connect, IPv6 host cannot be muted, dead pid, advisor rotate",
			model.Flag{ID: "r2", Rule: "sensitive-read-then-connect", Severity: 3, PID: 999, Agent: "claude",
				Evidence: []model.EvidenceItem{envRead, conn("2606:4700:20::681a:4a4:443")}, Advisor: adv("rotate-credentials")},
			[]string{"allow-host", "allow-path", "dismiss"}, ""},
		{"keychain-access, advisor mute",
			model.Flag{ID: "k1", Rule: "keychain-access", Severity: 1, PID: 999, Agent: "claude",
				Evidence: []model.EvidenceItem{{Kind: "keychain", Label: home + "/Library/Keychains/login.keychain-db"}}, Advisor: adv("mute-rule")},
			[]string{"allow-path", "mute-class", "dismiss"}, "mute-class"},
		{"keychain-security-cli, live pid, advisor kill",
			model.Flag{ID: "k2", Rule: "keychain-security-cli", Severity: 3, PID: 4242, Agent: "claude",
				Evidence: []model.EvidenceItem{{Kind: "exec", Label: "/usr/bin/security"}}, Advisor: adv("kill-agent")},
			[]string{"mute-class", "dismiss", "kill"}, "kill"},
		{"tcc-tamper",
			model.Flag{ID: "t1", Rule: "tcc-tamper", Severity: 3, PID: 999, Agent: "claude",
				Evidence: []model.EvidenceItem{{Kind: "tcc", Label: "kTCCServiceAccessibility"}}},
			[]string{"dismiss"}, ""},
		{"proxy-secret-leak, advisor mute",
			model.Flag{ID: "p1", Rule: "proxy-secret-leak", Severity: 3, Agent: "proxy",
				Evidence: []model.EvidenceItem{{Kind: "violation", Label: "proxy-secret-leak:aws-key"}, conn("api.example.com:443")}, Advisor: adv("mute-rule")},
			[]string{"allow-host", "mute-rule-host", "dismiss"}, "mute-rule-host"},
		{"secret-in-transcript",
			model.Flag{ID: "s", Rule: "secret-in-transcript", Severity: 2, Agent: "claude",
				Evidence: []model.EvidenceItem{{Kind: "transcript", Label: home + "/.claude/projects/p/abc.jsonl", Rule: "aws-access-key"}}},
			[]string{"dismiss"}, ""},
		{"acknowledged: no dismiss",
			model.Flag{ID: "ack", Rule: "tcc-tamper", Severity: 3, PID: 999, Agent: "claude", Acknowledged: true,
				Evidence: []model.EvidenceItem{{Kind: "tcc", Label: "kTCCServiceAccessibility"}}},
			[]string{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ex := a.explainFlag(c.f, false)
			if got := actionIDs(ex); !reflect.DeepEqual(got, c.ids) {
				t.Fatalf("actions = %v, want %v", got, c.ids)
			}
			if got := recommendedID(ex); got != c.rec {
				t.Fatalf("recommended = %q, want %q", got, c.rec)
			}
			for _, act := range ex.Actions {
				if act.Label == "" || act.Consequence == "" || act.Method == "" || act.Path == "" {
					t.Fatalf("action %+v is missing label/consequence/method/path", act)
				}
			}
		})
	}

	// allow-host is omitted once the host is allowlisted for the agent.
	if err := a.allowlist.Add("claude", "api.example.com"); err != nil {
		t.Fatal(err)
	}
	ex := a.explainFlag(cases[0].f, false)
	want := []string{"allow-host", "allow-path", "mute-rule-host", "open-incident", "dismiss", "kill"}
	if got := actionIDs(ex); !reflect.DeepEqual(got, want) {
		t.Fatalf("after allowlisting api.example.com: actions = %v, want %v", got, want)
	}
	if ex.Actions[0].Body["host"] != "cdn.example.net" {
		t.Fatalf("remaining allow-host targets %v, want cdn.example.net", ex.Actions[0].Body)
	}
}

// 9. Contract: the live FP flag's explanation, byte for byte.
func TestExplainGoldenSensitiveRead(t *testing.T) {
	pinExplainHome(t, "/Users/dev")
	a := explainTestAPI(t)
	f := liveFixtureFlag()
	a.store.PutFlag(f)
	a.store.PutAdvisorVerdict(f.ID, "flag", liveFixtureVerdict())
	a.store.PutIncident(model.IncidentReport{ID: "inc-1790121693-13250-12e7022e2de04005", FlagID: f.ID, PID: f.PID, Agent: "claude",
		Timestamp: f.TS, Rule: f.Rule, Subject: "2600:1f10:4fa9:a02:3441:aad6:bb1a:fd73:443"})
	stored, ok := a.lookupFlag(f.ID)
	if !ok {
		t.Fatal("fixture flag not found")
	}
	got, err := json.MarshalIndent(a.explainFlag(stored, false), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "explain_sensitive_read.json")
	if *updateGolden {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("explain JSON drifted from %s:\n--- got\n%s\n--- want\n%s", golden, got, want)
	}
}

// GET /flags/{id}/explain serves the full flag with the explanation; the
// exact /flags/acknowledge route still wins over the /flags/ subtree.
func TestFlagExplainHandler(t *testing.T) {
	pinExplainHome(t, "/Users/tester")
	a := explainTestAPI(t)
	f := model.Flag{ID: "h1", Rule: "proxy-secret-leak", Severity: 3, TS: time.Now(), Agent: "claude",
		Evidence: []model.EvidenceItem{{Kind: "violation", Label: "proxy-secret-leak:aws-key"}, {Kind: "connect", Label: "api.example.com:443"}}}
	a.store.PutFlag(f)
	a.store.PutAdvisorVerdict("h1", "flag", model.AdvisorVerdict{Assessment: "benign", Confidence: 0.9, Rationale: "Test key.", CreatedAt: time.Now()})
	mux := a.buildMux()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}

	rec := do(http.MethodGet, "/flags/h1/explain", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET explain = %d %s", rec.Code, rec.Body)
	}
	var got model.Flag
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "h1" || got.Title != "Secret leaving in agent traffic" || got.Explain == nil || got.Advisor == nil {
		t.Fatalf("explain response = %+v", got)
	}
	if got.Explain.Disposition.State != "benign-likely" || got.Explain.What != "Claude sent a secret (aws-key) to api.example.com." {
		t.Fatalf("explain = %+v", got.Explain)
	}
	if rec := do(http.MethodGet, "/flags/nope/explain", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", rec.Code)
	}
	if rec := do(http.MethodPost, "/flags/h1/explain", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST explain = %d, want 405", rec.Code)
	}
	for _, p := range []string{"/flags/h1", "/flags/h1/other", "/flags/", "/flags/h1/explain/x"} {
		if rec := do(http.MethodGet, p, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", p, rec.Code)
		}
	}
	// The exact acknowledge route still wins.
	if rec := do(http.MethodPost, "/flags/acknowledge", `{"flag_id":"h1"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"acknowledged":true`) {
		t.Fatalf("POST /flags/acknowledge = %d %s", rec.Code, rec.Body)
	}
	if rec := do(http.MethodGet, "/flags/acknowledge", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /flags/acknowledge = %d, want 405 from the acknowledge handler", rec.Code)
	}
}

// /flags stamps the explanation on the first 25 unacknowledged flags only.
func TestFlagsListStampsExplainOnFirst25Unacked(t *testing.T) {
	pinExplainHome(t, "/Users/tester")
	a := explainTestAPI(t)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 27; i++ {
		a.store.PutFlag(model.Flag{ID: "u" + string(rune('a'+i)), Rule: "tcc-tamper", Severity: 3, TS: base.Add(time.Duration(i) * time.Minute), Agent: "claude",
			Evidence: []model.EvidenceItem{{Kind: "tcc", Label: "kTCCServiceAccessibility"}}})
	}
	a.store.PutFlag(model.Flag{ID: "acked", Rule: "tcc-tamper", Severity: 3, TS: time.Now(), Agent: "claude"})
	a.store.AcknowledgeFlag("acked")
	rec := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/flags?limit=100", nil))
	var flags []model.Flag
	if err := json.Unmarshal(rec.Body.Bytes(), &flags); err != nil {
		t.Fatal(err)
	}
	stamped := 0
	for _, f := range flags {
		if f.ID == "acked" && f.Explain != nil {
			t.Fatal("acknowledged flag must stay raw")
		}
		if f.Explain != nil {
			stamped++
		}
	}
	if len(flags) != 28 || stamped != 25 {
		t.Fatalf("flags = %d, stamped = %d, want 28 and 25", len(flags), stamped)
	}
	snap := a.currentSnapshot()
	stamped = 0
	for _, f := range snap.Flags {
		if f.Explain != nil {
			stamped++
		}
	}
	if stamped != 25 {
		t.Fatalf("snapshot stamped = %d, want 25", stamped)
	}
}

// familyTitle title-cases only a plain harness name; an id carrying a
// namespace ("untagged:node") is served verbatim, in the sentence too.
func TestFamilyTitleKeepsIDs(t *testing.T) {
	for in, want := range map[string]string{
		"":              "Unknown",
		"claude":        "Claude",
		"claude-code":   "Claude-code",
		"codex":         "Codex",
		"untagged:node": "untagged:node",
		"untagged:bun":  "untagged:bun",
		"Cursor":        "Cursor",
	} {
		if got := familyTitle(in); got != want {
			t.Errorf("familyTitle(%q) = %q, want %q", in, got, want)
		}
	}
	a := explainTestAPI(t)
	f := model.Flag{ID: "w-untagged", Rule: "keychain-security-cli", Severity: 3, TS: time.Now(), PID: 4242, Agent: "untagged:node",
		Evidence: []model.EvidenceItem{{Kind: "exec", Label: "/usr/bin/security", Sub: "keychain CLI", TS: time.Now().Format(time.RFC3339)}}}
	ex := a.explainFlag(f, false)
	if !strings.Contains(ex.What, "untagged:node") || strings.Contains(ex.What, "Untagged") {
		t.Fatalf("what = %q, want the agent id untagged:node verbatim", ex.What)
	}
}
