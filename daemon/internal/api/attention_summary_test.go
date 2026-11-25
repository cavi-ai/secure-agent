package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

func TestPostureServesSummaryWithoutReclassifyingItsState(t *testing.T) {
	p := derivePosture(posture.Inputs{Generated: time.Now(), Status: posture.Status{Running: true}, Pending: []guard.Pending{{ID: "request", Agent: "claude", Tool: "Read", Path: "/work/.env"}}})
	if p.AttentionSummary == nil || p.AttentionSummary.Buckets[0].Count != 1 || p.NeedsYou != 1 || p.State != "attention" {
		t.Fatalf("posture: %+v", p)
	}
	empty := posture.DeriveAttentionSummary(nil, nil)
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
	p := derivePosture(posture.Inputs{Generated: time.Now(), Status: posture.Status{Running: true}, Pending: []guard.Pending{
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
	if s := posture.DeriveAttentionSummary(nil, nil); len(s.Buckets) != 3 || s.Buckets[0].Kind != AttentionBuckets[0] {
		t.Fatalf("buckets: %+v", s.Buckets)
	}
}

func TestPosturePublishesCategoryChangesAtUnchangedCounts(t *testing.T) {
	a := newTestAPI(Deps{Telemetry: TelemetryDeps{DeltaHub: NewDeltaHub()}})
	ch := a.deltaHub.Subscribe()
	defer a.deltaHub.Unsubscribe(ch)
	p := Posture{State: "attention", NeedsYou: 1, AttentionSummary: posture.DeriveAttentionSummary([]AttentionGroup{{Items: []AttentionItem{{Kind: "guard", ID: "one"}}}}, nil)}
	a.publishPosture(1, p, false)
	<-ch
	p.AttentionSummary = posture.DeriveAttentionSummary([]AttentionGroup{{Items: []AttentionItem{{Kind: "hook", ID: "two"}}}}, nil)
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
