package posture

import "testing"

func TestAttentionSummaryPreservesQueuePriorityAndCoverage(t *testing.T) {
	groups := []AttentionGroup{{Items: []AttentionItem{
		{Kind: "review", ID: "review", Priority: 2, Title: "Review evidence", SessionID: "session-a"},
		{Kind: "guard", ID: "guard", Priority: 5, Title: "Access request", SessionID: "session-b"},
		{Kind: "resource", ID: "resource", Priority: 4},
		{Kind: "hook", ID: "hook", Priority: 1},
		{Kind: "future-kind", ID: "future", Priority: 9},
	}}, {Items: []AttentionItem{{Kind: "incident", ID: "incident", Priority: 3, Title: "Incident"}, {Kind: "hook_delivery", ID: "delivery", Priority: 1}}}}
	coverage := []PostureItem{{Kind: "collector_down"}, {Kind: "uninspected_egress"}, {Kind: "hook_analysis_limit"}, {Kind: "storage_loss"}}
	s := DeriveAttentionSummary(groups, coverage)
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
