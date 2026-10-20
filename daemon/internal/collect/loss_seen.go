package collect

import (
	"sync/atomic"
	"time"
)

// LossSeen is when the operator last marked spool loss and bus drops as
// seen: a counter that has not grown since then no longer counts as growing.
type LossSeen struct{ at atomic.Int64 }

// Mark records that every loss up to at has been seen.
func (l *LossSeen) Mark(at time.Time) { l.at.Store(at.UnixNano()) }

// Growing is LossGrowing for a counter last grown at lastGrew, and false when
// that growth was marked seen.
func (l *LossSeen) Growing(lastGrew, now time.Time) bool {
	if l != nil {
		if seen := l.at.Load(); seen != 0 && !lastGrew.After(time.Unix(0, seen)) {
			return false
		}
	}
	return LossGrowing(lastGrew, now)
}
