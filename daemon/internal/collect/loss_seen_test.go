package collect

import (
	"testing"
	"time"
)

// Marking loss seen stops growth up to the mark from counting; later growth,
// or no mark at all, still counts.
func TestLossSeenStopsGrowthMarkedSeen(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var unmarked *LossSeen
	if !unmarked.Growing(now.Add(-time.Minute), now) {
		t.Fatal("unmarked loss a minute ago is not growing")
	}
	var seen LossSeen
	seen.Mark(now.Add(-30 * time.Second))
	if seen.Growing(now.Add(-time.Minute), now) {
		t.Fatal("loss before the mark still counts as growing")
	}
	if !seen.Growing(now.Add(-10*time.Second), now) {
		t.Fatal("loss after the mark does not count as growing")
	}
}
