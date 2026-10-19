package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
)

func TestAttentionSummaryPreservesQueuePriorityAndCoverage(t *testing.T) {
	groups := []AttentionGroup{{Items: []AttentionItem{
		{Kind: "review", ID: "review", Priority: 2, Title: "Review evidence", SessionID: "session-a"},
		{Kind: "guard", ID: "guard", Priority: 5, Title: "Access request", SessionID: "session-b"},
		{Kind: "resource", ID: "resource", Priority: 4},
		{Kind: "hook", ID: "hook", Priority: 1},
		{Kind: "future-kind", ID: "future", Priority: 9},
	}}, {Items: []AttentionItem{{Kind: "incident", ID: "incident", Priority: 3, Title: "Incident"}, {Kind: "hook_delivery", ID: "delivery", Priority: 1}}}}
	coverage := []PostureItem{{Kind: "collector_down"}, {Kind: "uninspected_egress"}, {Kind: "hook_analysis_limit"}, {Kind: "storage_loss"}}
	s := deriveAttentionSummary(groups, coverage)
	if s.Version != 1 || len(s.Buckets) != 4 {
		t.Fatalf("summary: %+v", s)
	}
	want := []struct {
		kind        string
		count, gaps int
		first       string
	}{{"decisions", 2, 0, "guard"}, {"security", 2, 0, "incident"}, {"monitoring", 2, 2, "hook"}, {"other", 1, 0, "future"}}
	for i, w := range want {
		b := s.Buckets[i]
		if b.Kind != w.kind || b.Count != w.count || b.CoverageCount != w.gaps || b.First == nil || b.First.ID != w.first {
			t.Fatalf("bucket %d: %+v", i, b)
		}
	}
	if s.Buckets[0].First.SessionID != "session-b" || groups[0].Items[0].ID != "review" {
		t.Fatal("identity or original queue order changed")
	}
}

func TestPostureServesSummaryWithoutReclassifyingItsState(t *testing.T) {
	p := derivePosture(postureInputs{Generated: time.Now(), Status: Status{Running: true}, Pending: []guard.Pending{{ID: "request", Agent: "claude", Tool: "Read", Path: "/work/.env"}}})
	if p.AttentionSummary == nil || p.AttentionSummary.Buckets[0].Count != 1 || p.NeedsYou != 1 || p.State != "attention" {
		t.Fatalf("posture: %+v", p)
	}
	empty := deriveAttentionSummary(nil, nil)
	if len(empty.Buckets) != 3 {
		t.Fatal("missing canonical categories")
	}
	for _, b := range empty.Buckets {
		if b.Count != 0 || b.CoverageCount != 0 || b.First != nil {
			t.Fatalf("invented attention: %+v", b)
		}
	}
}

// Every headline item pairs with the group item the clients match it to:
// the same kind, or the one PostureItemAttentionKinds names.
func TestPostureItemsPairWithTheirGroupItems(t *testing.T) {
	p := derivePosture(postureInputs{Generated: time.Now(), Status: Status{Running: true}, Pending: []guard.Pending{
		{ID: "a", Agent: "claude", Tool: "Read", Path: "/work/.env"},
		{ID: "b", Agent: "codex", Tool: "Read", Path: "/work/.aws/credentials"},
	}})
	if len(p.Items) != 2 {
		t.Fatalf("items: %+v", p.Items)
	}
	for _, item := range p.Items {
		want := item.Kind
		if alias, ok := PostureItemAttentionKinds[item.Kind]; ok {
			want = alias
		}
		matches := 0
		for _, g := range p.Groups {
			for _, gi := range g.Items {
				if gi.Kind == want && gi.ID == item.ID {
					matches++
				}
			}
		}
		if matches != 1 {
			t.Errorf("posture item %s/%s pairs with %d group items of kind %q, want 1", item.Kind, item.ID, matches, want)
		}
	}
	if s := deriveAttentionSummary(nil, nil); len(s.Buckets) != 3 || s.Buckets[0].Kind != AttentionBuckets[0] {
		t.Fatalf("buckets: %+v", s.Buckets)
	}
}

func TestPosturePublishesCategoryChangesAtUnchangedCounts(t *testing.T) {
	a := newTestAPI(Deps{Telemetry: TelemetryDeps{DeltaHub: NewDeltaHub()}})
	ch := a.deltaHub.Subscribe()
	defer a.deltaHub.Unsubscribe(ch)
	p := Posture{State: "attention", NeedsYou: 1, AttentionSummary: deriveAttentionSummary([]AttentionGroup{{Items: []AttentionItem{{Kind: "guard", ID: "one"}}}}, nil)}
	a.publishPosture(1, p, false)
	<-ch
	p.AttentionSummary = deriveAttentionSummary([]AttentionGroup{{Items: []AttentionItem{{Kind: "hook", ID: "two"}}}}, nil)
	a.publishPosture(2, p, false)
	select {
	case <-ch:
	default:
		t.Fatal("same-count category change was suppressed")
	}
	a.publishPosture(3, p, false)
	select {
	case <-ch:
		t.Fatal("unchanged summary published again")
	default:
	}
}
