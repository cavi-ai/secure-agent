package api

import (
	"context"
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
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func attentionAPI(t *testing.T, sessions []resource.Session) *API {
	t.Helper()
	a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.resources = func() resource.Snapshot { return resource.Snapshot{Sessions: sessions} }
	return a
}

// attentionGroups is the queue posture builds: over the store's 24 h
// patterns and routine groups.
func attentionGroups(a *API) []AttentionGroup {
	since := time.Now().Add(-24 * time.Hour)
	_, groups := a.attentionQueue(Status{Running: true}, a.computePatterns(since, patternDefaultMin), a.routineGroups(since))
	return groups
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
	if groups := attentionGroups(a); len(groups) != 0 {
		t.Fatalf("groups = %+v, want none", groups)
	}
}

func TestAttentionGroupsGuardPendingJoinsLiveSession(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(42, "codex", "/work/repo")})
	a.guardBroker = guard.NewBroker(time.Minute)
	// Request blocks until a decision lands; run it in the background and let
	// it time out after the test — the prompt stays pending meanwhile.
	go a.guardBroker.Request(context.Background(), guard.Pending{
		ID: "g1", Agent: "codex", Tool: "Bash", Path: "/Users/x/.ssh/id_ed25519",
	})
	waitFor(t, func() bool { return len(a.guardBroker.Pending()) == 1 })
	groups := attentionGroups(a)
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

func TestAttentionGroupLabelKeepsAgentIDCaseAtRootWorkspace(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(43, "cursor-ide", "/")})
	a.guardBroker = guard.NewBroker(time.Minute)
	go a.guardBroker.Request(context.Background(), guard.Pending{ID: "g3", Agent: "cursor-ide", Tool: "Read", Path: "/Users/x/.aws/credentials"})
	waitFor(t, func() bool { return len(a.guardBroker.Pending()) == 1 })
	groups := attentionGroups(a)
	if len(groups) != 1 || groups[0].Label != "cursor-ide" {
		t.Fatalf("groups = %+v, want one group labelled %q", groups, "cursor-ide")
	}
}

func TestAttentionGroupsUnmatchedGuardGetsAgentBucket(t *testing.T) {
	a := attentionAPI(t, nil)
	a.guardBroker = guard.NewBroker(time.Minute)
	go a.guardBroker.Request(context.Background(), guard.Pending{ID: "g2", Agent: "codex", Tool: "Write", Path: "/tmp/x"})
	waitFor(t, func() bool { return len(a.guardBroker.Pending()) == 1 })
	groups := attentionGroups(a)
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
	groups := attentionGroups(a)
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
	groups := attentionGroups(a)
	if len(groups) != 1 || len(groups[0].Items) != 1 || groups[0].Items[0].ID != "open" {
		t.Fatalf("groups = %+v, want only the unacknowledged flag", groups)
	}
}

// Legacy advice remains readable without lowering a detector's priority.
func TestAttentionGroupsFlagDisposition(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "claude", "/w")})
	a.store.PutFlag(model.Flag{ID: "fp", Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), PID: 1, Agent: "claude"})
	a.store.PutAdvisorVerdict("fp", "flag", model.AdvisorVerdict{Assessment: "benign", Confidence: 0.93, Rationale: "Own config.", CreatedAt: time.Now()})
	a.store.PutFlag(model.Flag{ID: "real", Rule: "tcc-tamper", Severity: 3, TS: time.Now(), PID: 1, Agent: "claude"})
	groups := attentionGroups(a)
	if len(groups) != 1 || len(groups[0].Items) != 2 {
		t.Fatalf("groups = %+v, want one group with two flag items", groups)
	}
	first, second := groups[0].Items[0], groups[0].Items[1]
	if first.ID != "real" || first.Priority != 2 || first.Title != "Critical finding" || first.Disposition == nil || first.Disposition.State != "critical" {
		t.Fatalf("first item = %+v, want the critical finding", first)
	}
	if second.ID != "fp" || second.Priority != 2 || second.Assessment == nil || second.Assessment.Risk != "unknown" || second.Disposition == nil || second.Disposition.State != "benign-likely" {
		t.Fatalf("second item = %+v, want separate risk and advice without lowered priority", second)
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
		Agents:     []AgentSummary{{PID: 42, Name: "cursor"}, {PID: 43, Name: "cursor"}},
		Collectors: []supervise.Health{{Name: "transcript", Running: true}},
	}
	a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status { return status })
	a.correlator = cr
	a.store.PutFlag(model.Flag{ID: "crit", Rule: "tcc-tamper", Severity: 3, TS: now, PID: 42, Agent: "cursor"})
	a.store.PutFlag(model.Flag{ID: "high", Rule: "keychain-access", Severity: 2, TS: now, PID: 42, Agent: "cursor"})

	p := a.computePosture()
	sum := 0
	groupOf := map[string][]string{}
	for _, g := range p.Groups {
		sum += len(g.Items)
		for _, it := range g.Items {
			groupOf[it.Kind+"|"+it.ID] = append(groupOf[it.Kind+"|"+it.ID], g.Key)
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
	coverage := map[string]bool{}
	for _, it := range p.CoverageItems {
		coverage[it.Kind] = true
	}
	for _, kind := range []string{"collector_silent", "harness_uncovered", "uninspected_egress"} {
		if !coverage[kind] {
			t.Fatalf("missing %s from coverage: %+v", kind, p.CoverageItems)
		}
	}
	if p.NeedsYou != 2 {
		t.Fatalf("needs_you=%d, want two actionable flags", p.NeedsYou)
	}
}

// A severity-2 flag ranks below the critical findings and carries its
// disposition and rule title.
func TestAttentionSeverityTwoFlagPriority(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "claude", "/w")})
	a.store.PutFlag(model.Flag{ID: "high", Rule: "keychain-access", Severity: 2, TS: time.Now(), PID: 1, Agent: "claude"})
	groups := attentionGroups(a)
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

// Raw uninspected egress is a coverage fact, not a pending decision. The
// status count already excludes known carriers.
func TestAttentionEgressCoverageSkipsCarriers(t *testing.T) {
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	tg := agents.New(cfg, twoAgentProcs{})
	tg.Refresh()
	now := time.Now()
	build := func(hosts ...string) (*API, *correlate.Correlator) {
		cr := correlate.New(tg, sensitive.New(cfg), cfg)
		for _, h := range hosts {
			cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 42, TS: now.Add(-time.Hour), RemoteHost: h, RemotePort: 443})
		}
		a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status {
			return Status{Running: true, UninspectedEgress: cr.UninspectedEgressCountWindow(24 * time.Hour)}
		})
		a.correlator = cr
		return a, cr
	}
	const carrier, unknown = "104.16.0.1", "unknown.example.com"

	a, cr := build(carrier, carrier, unknown)
	unknownCount := -1
	for _, row := range cr.UninspectedEgressSummarySince(time.Time{}) {
		switch row.Host {
		case carrier:
			if row.Infra == "" {
				t.Fatalf("carrier row %+v has no infra org; fixture is not a carrier", row)
			}
		case unknown:
			unknownCount = row.Count
		}
	}
	if unknownCount < 1 {
		t.Fatalf("unknown row missing from summary")
	}
	p := a.computePosture()
	if p.NeedsYou != 0 || p.CoverageCount != 1 || p.CoverageItems[0].Kind != "uninspected_egress" {
		t.Fatalf("posture = %+v, want one coverage item and no decisions", p)
	}

	a, _ = build(carrier)
	p = a.computePosture()
	if p.NeedsYou != 0 || p.CoverageCount != 0 {
		t.Fatalf("carrier-only posture = %+v, want no decisions or coverage gaps", p)
	}
}

func TestAttentionRecurringEgressRequiresAnOperatorDecision(t *testing.T) {
	a := attentionAPI(t, nil)
	scope := store.EgressScope{Agent: "claude", ExePath: "/Applications/Claude.app", Harness: "claude", Workspace: "/work/repo"}
	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 5; i++ {
		if err := a.store.RecordEgressObservationForTest(store.EgressObservation{
			Scope: scope, SessionID: "ended-session", Host: "updates.example.com", Protocol: "tcp", Port: 443,
			At: base.Add(time.Duration(i) * 30 * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	p := a.computePosture()
	if p.NeedsYou != 1 || len(p.Groups) != 1 || p.Groups[0].Key != "agent:claude" {
		t.Fatalf("posture = %+v, want one agent-level decision without guessed session", p)
	}
	it := p.Groups[0].Items[0]
	if it.Kind != "recurring_egress" || it.Action != "scope" || it.Count != 5 || it.ID == "" {
		t.Fatalf("recurring decision = %+v", it)
	}
	if _, err := a.store.CreateExpectedEgressRule(store.ExpectedEgressRule{
		Agent: scope.Agent, Kind: "scope", ExePath: scope.ExePath, Harness: scope.Harness, Workspace: scope.Workspace,
	}); err != nil {
		t.Fatal(err)
	}
	if got := a.computePosture().NeedsYou; got != 0 {
		t.Fatalf("expected activity still has %d pending decisions", got)
	}
}

// An incident's risk sets its headline severity: critical 3 (posture
// critical), high 2; only other risks age into severity 1.
func TestAttentionIncidentSeverityPreservesRisk(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		risk       model.RiskLevel
		ts         time.Time
		severity   int
		groupTitle string
	}{
		{"fresh critical", model.RiskCritical, now, 3, "Critical incident"},
		{"fresh high", model.RiskHigh, now, 2, "Open incident"},
		{"aging medium", model.RiskMedium, now.Add(-80 * time.Hour), 1, "Aging incident"},
		{"aging critical", model.RiskCritical, now.Add(-80 * time.Hour), 3, "Critical incident"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
			a.store.PutIncident(model.IncidentReport{ID: "inc-1", Rule: "sensitive-read-then-connect", Risk: tc.risk,
				Timestamp: tc.ts, Agent: "claude", PID: 7, Summary: "s"})
			p := a.computePosture()
			var headline *PostureItem
			for i := range p.Items {
				if p.Items[i].Kind == "incident" && p.Items[i].ID == "inc-1" {
					headline = &p.Items[i]
				}
			}
			if headline == nil || headline.Severity != tc.severity {
				t.Fatalf("headline = %+v, want severity %d\nitems=%+v", headline, tc.severity, p.Items)
			}
			title := ""
			for _, g := range p.Groups {
				for _, it := range g.Items {
					if it.Kind == "incident" && it.ID == "inc-1" {
						title = it.Title
					}
				}
			}
			if title != tc.groupTitle {
				t.Fatalf("group item title = %q, want %q", title, tc.groupTitle)
			}
			if tc.risk == model.RiskCritical && p.State != "critical" {
				t.Fatalf("posture state = %q, want critical", p.State)
			}
		})
	}
}
