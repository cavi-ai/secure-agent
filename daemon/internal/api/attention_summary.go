package api

// AttentionSummary is an additive presentation of the existing queue. Queued
// counts still sum to needs_you; coverage gaps are counted separately.
type AttentionSummary struct {
	Version int               `json:"version"`
	Buckets []AttentionBucket `json:"buckets"`
}

type AttentionBucket struct {
	Kind          string              `json:"kind"`
	Count         int                 `json:"count"`
	CoverageCount int                 `json:"coverage_count"`
	First         *AttentionReference `json:"first,omitempty"`
}

// AttentionReference points to an existing group item, never a new authority
// to approve access or a substitute for the item's current evidence.
type AttentionReference struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	SessionID string `json:"session_id,omitempty"`
}

func deriveAttentionSummary(groups []AttentionGroup, coverage []PostureItem) *AttentionSummary {
	s := &AttentionSummary{Version: 1, Buckets: []AttentionBucket{{Kind: "decisions"}, {Kind: "security"}, {Kind: "monitoring"}, {Kind: "other"}}}
	priorities := [4]int{}
	for _, group := range groups {
		for _, item := range group.Items {
			i := 3
			switch item.Kind {
			case "guard", "resource":
				i = 0
			case "review", "incident", "flag", "pattern", "routine":
				i = 1
			case "hook", "hook_delivery":
				i = 2
			}
			b := &s.Buckets[i]
			b.Count++
			if b.First == nil || item.Priority > priorities[i] {
				b.First = &AttentionReference{Kind: item.Kind, ID: item.ID, Title: item.Title, SessionID: item.SessionID}
				priorities[i] = item.Priority
			}
		}
	}
	for _, item := range coverage {
		if isMonitoringGap(item) {
			s.Buckets[2].CoverageCount++
		}
	}
	if s.Buckets[3].Count == 0 {
		s.Buckets = s.Buckets[:3]
	}
	return s
}

func isMonitoringGap(item PostureItem) bool {
	return item.Kind != "uninspected_egress" && item.Kind != "hook_analysis_limit"
}
