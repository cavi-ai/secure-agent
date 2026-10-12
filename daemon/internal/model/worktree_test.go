package model

import (
	"testing"
	"time"
)

func TestWorkspaceActivityActiveAt(t *testing.T) {
	now := time.Date(2026, 10, 12, 19, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		a    WorkspaceActivity
		want bool
	}{
		{"live session", WorkspaceActivity{Live: true}, true},
		{"ended, seen 2 minutes ago", WorkspaceActivity{LastSeen: now.Add(-2 * time.Minute)}, true},
		{"ended, seen just inside the window", WorkspaceActivity{LastSeen: now.Add(-WorkspaceActiveWindow + time.Second)}, true},
		{"ended, seen at the window", WorkspaceActivity{LastSeen: now.Add(-WorkspaceActiveWindow)}, false},
		{"ended an hour ago", WorkspaceActivity{LastSeen: now.Add(-time.Hour)}, false},
		{"never seen", WorkspaceActivity{}, false},
	} {
		if got := c.a.ActiveAt(now); got != c.want {
			t.Errorf("%s: ActiveAt = %v, want %v", c.name, got, c.want)
		}
	}
}
