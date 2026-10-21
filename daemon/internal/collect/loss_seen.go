package collect

import (
	"sync/atomic"
	"time"
)

// LossSeen is when the operator last marked spool loss and bus drops as
// seen: a counter that has not grown since then no longer counts as growing.
type LossSeen struct{ at atomic.Int64 }

// SeenAt is the reviewed cutoff, independent of current delivery health.
func (l *LossSeen) SeenAt() time.Time {
	if l != nil {
		if at := l.at.Load(); at != 0 {
			return time.Unix(0, at).UTC()
		}
	}
	return time.Time{}
}

// Mark records that every loss up to at has been seen.
func (l *LossSeen) Mark(at time.Time) {
	for {
		previous := l.at.Load()
		if at.UnixNano() <= previous || l.at.CompareAndSwap(previous, at.UnixNano()) {
			return
		}
	}
}

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
