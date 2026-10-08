package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func agentFlag(f model.Flag, agent string) model.Flag {
	f.Agent = agent
	return f
}

func dockerRead(path string) model.EvidenceItem {
	return model.EvidenceItem{Kind: "read", Label: path, Sub: "sensitive read", PID: 900, Exe: "/Applications/Docker.app/Contents/Resources/bin/docker"}
}

// One process reading one file under several agents is one group; a home
// dot-directory gathers its files; a single agent on a single file stays a
// pattern; a group needs routineMin flags.
func TestRoutineGroupsSpanAgentsAndFiles(t *testing.T) {
	a := expectedTestAPI(t)
	now := time.Now()
	gh := ghRead("sensitive read", 900, "GitHub")
	for i, agent := range []string{"claude", "codex", "openclaw", "codex"} {
		a.store.PutFlag(agentFlag(ghFlag(fmt.Sprintf("gh%d", i), now.Add(time.Duration(i)*time.Minute), gh, fmt.Sprintf("140.82.114.%d", i)), agent))
	}
	a.store.PutFlag(agentFlag(ghFlag("dk1", now, dockerRead("/Users/dev/.docker/config.json"), "uf-in-f84.1e100.net"), "codex"))
	a.store.PutFlag(agentFlag(ghFlag("dk2", now, dockerRead("/Users/dev/.docker/config.json"), "vt-in-x5e.1e100.net"), "codex"))
	a.store.PutFlag(agentFlag(ghFlag("dk3", now, dockerRead("/Users/dev/.docker/contexts/meta/ab12/meta.json"), "uf-in-f84.1e100.net"), "codex"))
	cat := model.EvidenceItem{Kind: "read", Label: "/Users/dev/work/.env", Sub: "sensitive read", PID: 900, Exe: "/bin/cat"}
	for i := 0; i < 3; i++ {
		a.store.PutFlag(ghFlag(fmt.Sprintf("one%d", i), now, cat, "api.example.com"))
	}
	noReader := model.EvidenceItem{Kind: "read", Label: "/Users/dev/.zshenv", Sub: "sensitive read"}
	a.store.PutFlag(agentFlag(ghFlag("z1", now, noReader, "api.example.com"), "claude"))
	a.store.PutFlag(agentFlag(ghFlag("z2", now, noReader, "api.example.com"), "codex"))

	groups := a.routineGroups(now.Add(-time.Hour))
	if len(groups) != 2 {
		t.Fatalf("groups = %+v, want gh and docker", groups)
	}
	g := groups[0]
	if g.Key != "routine|gh|/Users/dev/.config" || g.Reader != "gh" || g.Area != "~/.config/gh/hosts.yml" || g.Files != 1 || g.Count != 4 ||
		strings.Join(g.Agents, ",") != "codex,claude,openclaw" || g.DestinationCount != 1 || g.Expectable != 4 {
		t.Fatalf("gh group = %+v", g)
	}
	if g.Summary != "gh read ~/.config/gh/hosts.yml, then connected to GitHub — 4 times across 3 agents." {
		t.Fatalf("summary = %q", g.Summary)
	}
	if len(g.Actions) != 2 || g.Actions[0].ID != "expect-all" || g.Actions[0].Path != "/expected" || g.Actions[1].ID != "dismiss-all" ||
		len(g.Actions[0].Body["flag_ids"].([]string)) != 4 || g.Actions[1].Label != "Dismiss all 4" {
		t.Fatalf("gh actions = %+v", g.Actions)
	}
	d := groups[1]
	if d.Reader != "docker" || d.Area != "~/.docker" || d.Files != 2 || d.Count != 3 || len(d.Agents) != 1 {
		t.Fatalf("docker group = %+v", d)
	}
	if !strings.HasPrefix(d.Summary, "docker read 2 files in ~/.docker, then connected to ") {
		t.Fatalf("docker summary = %q", d.Summary)
	}
	for _, g := range groups {
		if strings.Contains(g.Key, ".env") || strings.Contains(g.Key, ".zshenv") {
			t.Fatalf("unexpected group %s", g.Key)
		}
	}

	a.store.PutFlag(agentFlag(ghFlag("z3", now, noReader, "api.example.com"), "opencode"))
	var z model.RoutineGroup
	for _, g := range a.routineGroups(now.Add(-time.Hour)) {
		if g.Reader == "" {
			z = g
		}
	}
	if z.Count != 3 || z.Expectable != 0 || len(z.Actions) != 1 || z.Actions[0].ID != "dismiss-all" ||
		!strings.HasPrefix(z.Summary, "A process with no recorded name read ~/.zshenv") {
		t.Fatalf("readerless group = %+v", z)
	}
}

// Treat as routine never expects a read the group does not name: a flag that
// also cites another reader or file stays out of the bulk request.
func TestRoutineExpectsOnlyTheGroupsReads(t *testing.T) {
	a := expectedTestAPI(t)
	now := time.Now()
	gh := ghRead("sensitive read", 900, "GitHub")
	for i, agent := range []string{"claude", "codex", "openclaw"} {
		a.store.PutFlag(agentFlag(ghFlag(fmt.Sprintf("gh%d", i), now, gh, "140.82.114.6"), agent))
	}
	mixed := agentFlag(ghFlag("mixed", now.Add(time.Minute), gh, "140.82.114.6"), "codex")
	mixed.Evidence = append(mixed.Evidence, model.EvidenceItem{Kind: "read", Label: "/Users/dev/work/.env", Sub: "sensitive read", PID: 901, Exe: "/tmp/go-build/api.test"})
	a.store.PutFlag(mixed)

	groups := a.routineGroups(now.Add(-time.Hour))
	if len(groups) != 1 || groups[0].Count != 4 || groups[0].Expectable != 3 {
		t.Fatalf("groups = %+v", groups)
	}
	expect := groups[0].Actions[0]
	ids := expect.Body["flag_ids"].([]string)
	if expect.ID != "expect-all" || len(ids) != 3 || strings.Contains(strings.Join(ids, ","), "mixed") ||
		!strings.HasSuffix(expect.Consequence, " 1 flag that cites another reader or file stays open for its own review.") {
		t.Fatalf("expect-all = %+v", expect)
	}
	if dismiss := groups[0].Actions[1]; len(dismiss.Body["flag_ids"].([]string)) != 4 {
		t.Fatalf("dismiss-all = %+v", dismiss)
	}
	body, _ := json.Marshal(expect.Body)
	if w := call(t, a, "POST", "/expected", string(body)); w.Code != 200 {
		t.Fatalf("POST status %d: %s", w.Code, w.Body)
	}
	for _, p := range a.expected.List() {
		if p.Reader != "gh" || p.Path != ghHosts {
			t.Fatalf("expected a read the group does not name: %+v", p)
		}
	}
	if f, _ := a.store.GetFlag("mixed"); f.Acknowledged {
		t.Fatal("the mixed flag was reviewed by the bulk expectation")
	}
}

// The attention queue shows a routine group once, in the routine group,
// ahead of agent groups of equal priority; its flags leave the agent groups.
func TestAttentionFoldsRoutineAcrossAgents(t *testing.T) {
	a := expectedTestAPI(t)
	now := time.Now()
	gh := ghRead("sensitive read", 900, "GitHub")
	for i, agent := range []string{"claude", "codex", "openclaw"} {
		f := agentFlag(ghFlag(fmt.Sprintf("gh%d", i), now.Add(time.Duration(i)*time.Minute), gh, "140.82.114.6"), agent)
		f.Severity = 2
		a.store.PutFlag(f)
	}
	other := ghFlag("solo", now, model.EvidenceItem{Kind: "read", Label: "/Users/dev/work/.env", Sub: "sensitive read", PID: 900, Exe: "/bin/cat"}, "api.example.com")
	other.Severity = 2
	a.store.PutFlag(other)

	groups := attentionGroups(a)
	if len(groups) < 2 || groups[0].Key != routineGroupKey || len(groups[0].Items) != 1 {
		t.Fatalf("groups = %+v, want the routine group first with one item", groups)
	}
	it := groups[0].Items[0]
	if it.Kind != "routine" || it.ID != "routine|gh|/Users/dev/.config" || it.Count != 3 || it.Disposition == nil {
		t.Fatalf("routine item = %+v", it)
	}
	for _, g := range groups[1:] {
		for _, it := range g.Items {
			if it.ID == "gh0" || it.ID == "gh1" || it.ID == "gh2" || strings.Contains(it.ID, "hosts.yml") && it.Kind != "routine" {
				t.Fatalf("covered flag left in %s: %+v", g.Key, it)
			}
		}
	}
	p := a.computePosture()
	n := 0
	for _, it := range p.Items {
		if it.Kind == "routine" {
			n++
		}
	}
	if n != 1 || p.NeedsYou != len(p.Items) {
		t.Fatalf("posture items = %+v", p.Items)
	}
}

// POST /expected {"flag_ids"} marks every exact pair those flags cite,
// reviews the ones now covered, and leaves a reader-less flag open.
func TestExpectFlagsMarksEveryPair(t *testing.T) {
	a := expectedTestAPI(t)
	now := time.Now()
	gh := ghRead("sensitive read", 900, "GitHub")
	a.store.PutFlag(ghFlag("a", now, gh, "140.82.114.6"))
	a.store.PutFlag(agentFlag(ghFlag("b", now, gh, "140.82.114.7"), "codex"))
	a.store.PutFlag(ghFlag("later", now, gh, "140.82.114.8"))
	noReader := ghFlag("noreader", now, model.EvidenceItem{Kind: "read", Label: ghHosts, Sub: "sensitive read"}, "140.82.114.6")
	a.store.PutFlag(noReader)

	w := call(t, a, "POST", "/expected", `{"flag_ids":["a","b","noreader","missing"]}`)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got map[string]int
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got["added"] != 2 || got["acknowledged"] != 2 {
		t.Fatalf("response = %s (%v)", w.Body, err)
	}
	for id, acked := range map[string]bool{"a": true, "b": true, "later": false, "noreader": false} {
		if f, _ := a.store.GetFlag(id); f.Acknowledged != acked {
			t.Errorf("%s acknowledged = %v, want %v", id, f.Acknowledged, acked)
		}
	}
	if keys := len(a.expected.List()); keys != 2 {
		t.Fatalf("expected patterns = %d, want 2 exact pairs", keys)
	}
	if audit := a.store.RecentAudit(1); len(audit) != 1 || !strings.Contains(audit[0].Detail, "expected 2 exact reader, file and destination pairs from 4 flags") {
		t.Fatalf("audit = %+v", audit)
	}
	if w := call(t, a, "POST", "/expected", `{"flag_ids":["a","b"]}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"added":0`) {
		t.Fatalf("repeat: %d %s", w.Code, w.Body)
	}
	if w := call(t, a, "POST", "/expected", `{"flag_ids":["noreader"]}`); w.Code != 422 {
		t.Fatalf("reader-less only: status %d, want 422", w.Code)
	}
	if w := call(t, a, "POST", "/expected", `{"flag_id":"a","flag_ids":["b"]}`); w.Code != 400 {
		t.Fatalf("both forms: status %d, want 400", w.Code)
	}
	ids := make([]string, model.PatternFlagIDCap+1)
	for i := range ids {
		ids[i] = fmt.Sprint(i)
	}
	body, _ := json.Marshal(map[string]any{"flag_ids": ids})
	if w := call(t, a, "POST", "/expected", string(body)); w.Code != 400 {
		t.Fatalf("over the cap: status %d, want 400", w.Code)
	}
}
