package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func attentionAPI(t *testing.T, sessions []resource.Session) *API {
	t.Helper()
	a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.resources = func() resource.Snapshot { return resource.Snapshot{Sessions: sessions} }
	return a
}

func mkResourceSession(rootPid int32, name, cwd string) resource.Session {
	return resource.Session{
		Key:        "key-" + name,
		RootPID:    rootPid,
		Name:       name,
		Workspace:  cwd,
		LastSeenAt: time.Now().Format(time.RFC3339),
		Processes:  []resource.Process{{PID: rootPid}},
	}
}

// waitFor polls a condition with a short deadline — the guard broker enqueues
// asynchronously from Request's goroutine.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}

func TestAttentionGroupsEmptyWhenNothingPending(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "codex", "/work/a")})
	if _, groups := a.attentionQueue(Status{Running: true}); len(groups) != 0 {
		t.Fatalf("groups = %+v, want none", groups)
	}
}

func TestAttentionGroupsGuardPendingJoinsLiveSession(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(42, "codex", "/work/repo")})
	a.guardBroker = guard.NewBroker(time.Minute)
	// Request blocks until a decision lands; run it in the background and let
	// it time out after the test — the prompt stays pending meanwhile.
	go a.guardBroker.Request(guard.Pending{
		ID: "g1", Agent: "codex", Tool: "Bash", Path: "/Users/x/.ssh/id_ed25519",
	})
	waitFor(t, func() bool { return len(a.guardBroker.Pending()) == 1 })
	_, groups := a.attentionQueue(Status{Running: true})
	if len(groups) != 1 {
		t.Fatalf("groups = %+v, want 1", groups)
	}
	g := groups[0]
	if g.RootPID != 42 || g.Agent != "codex" {
		t.Fatalf("group not anchored to the session: %+v", g)
	}
	if len(g.Items) != 1 || g.Items[0].Kind != "guard" || g.Items[0].Priority != 5 {
		t.Fatalf("items = %+v, want one guard item at priority 5", g.Items)
	}
}

func TestAttentionGroupsUnmatchedGuardGetsAgentBucket(t *testing.T) {
	a := attentionAPI(t, nil)
	a.guardBroker = guard.NewBroker(time.Minute)
	go a.guardBroker.Request(guard.Pending{ID: "g2", Agent: "codex", Tool: "Write", Path: "/tmp/x"})
	waitFor(t, func() bool { return len(a.guardBroker.Pending()) == 1 })
	_, groups := a.attentionQueue(Status{Running: true})
	if len(groups) != 1 || groups[0].RootPID != 0 {
		t.Fatalf("groups = %+v, want one ungrouped bucket", groups)
	}
}

func TestAttentionGroupsResourcePressureUsesControlAction(t *testing.T) {
	sess := mkResourceSession(7, "claude", "/work/big")
	sess.RSSBytes = 5 << 30
	sess.CPUPercent = 150
	sess.Diagnoses = []resource.Diagnosis{{Code: "memory-hog", Summary: "Claude is using 5.0 GiB"}}
	sess.Control = &resource.SessionControl{PendingID: "d1", NextAction: resource.ActionTerminate}
	a := attentionAPI(t, []resource.Session{sess})
	_, groups := a.attentionQueue(Status{Running: true})
	if len(groups) != 1 {
		t.Fatalf("groups = %+v, want 1", groups)
	}
	g := groups[0]
	if g.RSSBytes != 5<<30 || g.CPUPercent != 150 {
		t.Fatalf("group missing resource stats: %+v", g)
	}
	if len(g.Items) != 1 || string(g.Items[0].Action) != string(resource.ActionTerminate) {
		t.Fatalf("items = %+v, want one restart item", g.Items)
	}
	if g.Items[0].Detail != "Claude is using 5.0 GiB" {
		t.Fatalf("detail = %q, want the diagnosis summary", g.Items[0].Detail)
	}
}

func TestAttentionGroupsAcknowledgedFlagsExcluded(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "codex", "/w")})
	a.store.PutFlag(model.Flag{ID: "open", Rule: "tcc-tamper", Severity: 3, TS: time.Now(), PID: 1, Agent: "codex"})
	a.store.PutFlag(model.Flag{ID: "done", Rule: "proxy-secret-leak", Severity: 3, TS: time.Now(), PID: 1, Agent: "codex"})
	a.store.AcknowledgeFlag("done")
	_, groups := a.attentionQueue(Status{Running: true})
	if len(groups) != 1 || len(groups[0].Items) != 1 || groups[0].Items[0].ID != "open" {
		t.Fatalf("groups = %+v, want only the unacknowledged flag", groups)
	}
}

// Flag items carry their disposition; a likely-benign one drops below the
// critical findings.
func TestAttentionGroupsFlagDisposition(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "claude", "/w")})
	a.store.PutFlag(model.Flag{ID: "fp", Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), PID: 1, Agent: "claude"})
	a.store.PutAdvisorVerdict("fp", "flag", model.AdvisorVerdict{Assessment: "benign", Confidence: 0.93, Rationale: "Own config.", CreatedAt: time.Now()})
	a.store.PutFlag(model.Flag{ID: "real", Rule: "tcc-tamper", Severity: 3, TS: time.Now(), PID: 1, Agent: "claude"})
	_, groups := a.attentionQueue(Status{Running: true})
	if len(groups) != 1 || len(groups[0].Items) != 2 {
		t.Fatalf("groups = %+v, want one group with two flag items", groups)
	}
	first, second := groups[0].Items[0], groups[0].Items[1]
	if first.ID != "real" || first.Priority != 2 || first.Title != "Critical finding" || first.Disposition == nil || first.Disposition.State != "critical" {
		t.Fatalf("first item = %+v, want the critical finding", first)
	}
	if second.ID != "fp" || second.Priority != 1 || second.Title != "Finding, likely benign" || second.Disposition == nil || second.Disposition.State != "benign-likely" {
		t.Fatalf("second item = %+v, want the likely-benign finding", second)
	}
}

// twoAgentProcs: one cursor and one codex process, so uninspected egress
// rolls up for two agents.
type twoAgentProcs struct{}

func (twoAgentProcs) List() []agents.ProcInfo {
	return []agents.ProcInfo{
		{PID: 42, PPID: 1, Exe: "/usr/local/bin/cursor-agent"},
		{PID: 43, PPID: 1, Exe: "/usr/local/bin/codex"},
	}
}

func (p twoAgentProcs) Info(pid int32) (agents.ProcInfo, bool) {
	for _, info := range p.List() {
		if info.PID == pid {
			return info, true
		}
	}
	return agents.ProcInfo{}, false
}

// attentionKind maps a headline item kind to its group item kind.
func attentionKind(kind string) string {
	switch kind {
	case "guard_pending":
		return "guard"
	case "resource_pressure":
		return "resource"
	case "uninspected_egress":
		return "egress"
	}
	return kind
}

// The hero count and the Attention tab count one set: every headline item
// sits in exactly one group and the group items sum to needs_you.
func TestAttentionGroupsCoverEveryPostureItem(t *testing.T) {
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, twoAgentProcs{})
	tg.Refresh()
	cr := correlate.New(tg, sensitive.New(cfg), cfg)
	now := time.Now()
	cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 42, TS: now.Add(-time.Hour), RemoteHost: "one.example.com", RemotePort: 443})
	cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 43, TS: now.Add(-time.Hour), RemoteHost: "two.example.com", RemotePort: 443})

	status := Status{
		Running: true, ActiveAgents: 2, Uptime: "1h", UninspectedEgress: 2,
		Collectors: []supervise.Health{{Name: "transcript", Running: true}},
	}
	a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status { return status })
	a.correlator = cr
	a.store.PutFlag(model.Flag{ID: "crit", Rule: "tcc-tamper", Severity: 3, TS: now, PID: 42, Agent: "cursor"})
	a.store.PutFlag(model.Flag{ID: "high", Rule: "keychain-access", Severity: 2, TS: now, PID: 42, Agent: "cursor"})

	p := a.computePosture()
	sum := 0
	groupOf := map[string][]string{}
	egressGroups := 0
	for _, g := range p.Groups {
		sum += len(g.Items)
		for _, it := range g.Items {
			groupOf[it.Kind+"|"+it.ID] = append(groupOf[it.Kind+"|"+it.ID], g.Key)
			if it.Kind == "egress" {
				egressGroups++
			}
		}
	}
	if sum != p.NeedsYou || len(p.Items) != p.NeedsYou {
		t.Fatalf("group items = %d, items = %d, needs_you = %d; want all equal\nitems=%+v\ngroups=%+v", sum, len(p.Items), p.NeedsYou, p.Items, p.Groups)
	}
	for _, it := range p.Items {
		if keys := groupOf[attentionKind(it.Kind)+"|"+it.ID]; len(keys) != 1 {
			t.Fatalf("item %s %q is in groups %v, want exactly one", it.Kind, it.ID, keys)
		}
	}
	if keys := groupOf["flag|high"]; len(keys) != 1 || keys[0] == machineGroupKey {
		t.Fatalf("severity-2 flag groups = %v, want one agent group", keys)
	}
	if keys := groupOf["collector_silent|transcript"]; len(keys) != 1 || keys[0] != machineGroupKey {
		t.Fatalf("silent collector groups = %v, want [machine]", keys)
	}
	if keys := groupOf["harness_uncovered|harness-hooks"]; len(keys) != 1 || keys[0] != machineGroupKey {
		t.Fatalf("uncovered harness groups = %v, want [machine]", keys)
	}
	if egressGroups != 2 {
		t.Fatalf("egress group items = %d, want one per agent (2)", egressGroups)
	}
	for _, g := range p.Groups {
		if g.Key == machineGroupKey && (g.Agent != "" || g.Label != "This machine") {
			t.Fatalf("machine group = %+v, want agent \"\" and label \"This machine\"", g)
		}
	}
}

// A severity-2 flag ranks below the critical findings and carries its
// disposition and rule title.
func TestAttentionSeverityTwoFlagPriority(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "claude", "/w")})
	a.store.PutFlag(model.Flag{ID: "high", Rule: "keychain-access", Severity: 2, TS: time.Now(), PID: 1, Agent: "claude"})
	_, groups := a.attentionQueue(Status{Running: true})
	if len(groups) != 1 || len(groups[0].Items) != 1 {
		t.Fatalf("groups = %+v, want one group with the flag", groups)
	}
	it := groups[0].Items[0]
	if it.Kind != "flag" || it.ID != "high" || it.Priority != 1 || it.Title != "Agent touched the keychain" {
		t.Fatalf("item = %+v, want priority 1 titled by the rule", it)
	}
	if it.Disposition == nil || it.Disposition.State != model.DispositionWarning {
		t.Fatalf("disposition = %+v, want warning", it.Disposition)
	}
}
