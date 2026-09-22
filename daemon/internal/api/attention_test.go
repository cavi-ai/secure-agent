package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
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
	if groups := a.computeAttentionGroups(Status{Running: true}); len(groups) != 0 {
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
	groups := a.computeAttentionGroups(Status{Running: true})
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
	groups := a.computeAttentionGroups(Status{Running: true})
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
	groups := a.computeAttentionGroups(Status{Running: true})
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
	groups := a.computeAttentionGroups(Status{Running: true})
	if len(groups) != 1 || len(groups[0].Items) != 1 || groups[0].Items[0].ID != "open" {
		t.Fatalf("groups = %+v, want only the unacknowledged flag", groups)
	}
}
