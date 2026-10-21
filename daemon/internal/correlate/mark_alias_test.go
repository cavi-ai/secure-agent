package correlate

import (
	"testing"
	"time"
)

// A recent-marks lookup stores the pid's list under the direct pid too; later
// appends and consumed marks under one pid must not rewrite the other's list.
func TestRecentMarksKeepPIDListsApart(t *testing.T) {
	c := newTestCorrelator(t)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range []string{"a", "b", "c"} {
		c.rememberReadLocked(10, 0, readMark{path: p, at: now})
		c.rememberConnLocked(10, 0, connMark{host: p, at: now})
	}
	c.recentReadsLocked(10, 20, now, window)
	c.recentConnsLocked(10, 20, now, window)

	c.rememberReadLocked(10, 0, readMark{path: "pid-10", at: now})
	c.rememberReadLocked(20, 0, readMark{path: "pid-20", at: now})
	c.rememberConnLocked(10, 0, connMark{host: "pid-10", at: now})
	c.rememberConnLocked(20, 0, connMark{host: "pid-20", at: now})
	if got := c.marks[10][len(c.marks[10])-1].path; got != "pid-10" {
		t.Fatalf("pid 10's newest read = %q, overwritten through pid 20", got)
	}
	if got := c.conns[10][len(c.conns[10])-1].host; got != "pid-10" {
		t.Fatalf("pid 10's newest conn = %q, overwritten through pid 20", got)
	}

	c.markReadConsumedLocked(20, 0)
	c.markConnConsumedLocked(20, 0)
	for _, m := range c.marks[10] {
		if m.consumed {
			t.Fatalf("consuming pid 20's reads consumed pid 10's %q", m.path)
		}
	}
	for _, m := range c.conns[10] {
		if m.consumed {
			t.Fatalf("consuming pid 20's conns consumed pid 10's %q", m.host)
		}
	}
}
