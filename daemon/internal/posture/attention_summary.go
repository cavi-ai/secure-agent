package posture

// AttentionBuckets are the summary's buckets in served order; clients
// validate against this order (lib.js ATTENTION_BUCKETS, Models.swift
// attentionBuckets, pinned by a drift test in daemon/internal/wiregen).
var AttentionBuckets = []string{"decisions", "security", "monitoring", "other"}

// PostureItemAttentionKinds maps a posture item's kind to the kind of the
// group item that represents it, where they differ; clients use it to match
// the two (lib.js POSTURE_ITEM_ATTENTION_KINDS, Models.swift
// postureItemAttentionKinds).
var PostureItemAttentionKinds = map[string]string{"guard_pending": "guard", "resource_pressure": "resource"}

// attentionBucket is the index in AttentionBuckets of a group item kind;
// unknown kinds count as "other".
func attentionBucket(kind string) int {
	switch kind {
	case "guard", "resource":
		return 0
	case "review", "incident", "flag", "pattern", "routine":
		return 1
	case "hook", "hook_delivery":
		return 2
	}
	return 3
}

// DeriveAttentionSummary counts group items per bucket, keeps each bucket's
// highest-priority item, and counts active coverage gaps under monitoring.
func DeriveAttentionSummary(groups []AttentionGroup, coverage []PostureItem) *AttentionSummary {
	s := &AttentionSummary{Version: 1}
	for _, kind := range AttentionBuckets {
		s.Buckets = append(s.Buckets, AttentionBucket{Kind: kind})
	}
	priorities := [4]int{}
	for _, group := range groups {
		for _, item := range group.Items {
			i := attentionBucket(item.Kind)
			b := &s.Buckets[i]
			b.Count++
			if b.First == nil || item.Priority > priorities[i] {
				b.First = &AttentionReference{Kind: item.Kind, ID: item.ID, Title: item.Title, SessionID: item.SessionID}
				priorities[i] = item.Priority
			}
		}
	}
	for _, item := range coverage {
		if IsMonitoringGap(item) {
			s.Buckets[2].CoverageCount++
		}
	}
	if s.Buckets[3].Count == 0 {
		s.Buckets = s.Buckets[:3]
	}
	return s
}

// IsMonitoringGap reports whether item is a current monitoring failure.
func IsMonitoringGap(item PostureItem) bool {
	switch item.MonitoringState {
	case MonitoringHistorical, MonitoringInformational, MonitoringDisabled:
		return false
	case MonitoringActive:
		return true
	}
	return item.Kind != "uninspected_egress" && item.Kind != "hook_analysis_limit" && item.Kind != "collector_idle"
}
