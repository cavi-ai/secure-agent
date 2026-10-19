package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectorStatusRejectsStaleOrForeignEvidence(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "status.json")
	for _, tc := range []struct {
		name  string
		pid   int
		state string
		at    time.Time
		want  bool
	}{
		{"denied", 42, "permission_denied", now, true},
		{"collecting", 42, "collecting", now, true},
		{"previous-process", 41, "permission_denied", now, false},
		{"stale", 42, "permission_denied", now.Add(-2 * time.Minute), false},
		{"future", 42, "collecting", now.Add(time.Minute), false},
		{"unknown-state", 42, "authorized", now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(ESCollectorStatus{PID: tc.pid, State: tc.state, UpdatedAt: tc.at})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if got := readESCollectorStatus(path, 42, now); (got != nil) != tc.want {
				t.Fatalf("status = %+v, want accepted=%v", got, tc.want)
			}
		})
	}
	for _, data := range []string{"not json", strings.Repeat(" ", 4097), `{}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if got := readESCollectorStatus(path, 42, now); got != nil {
			t.Fatalf("invalid status accepted: %+v", got)
		}
	}
	link := filepath.Join(t.TempDir(), "link.json")
	data, _ := json.Marshal(ESCollectorStatus{PID: 42, State: "collecting", UpdatedAt: now})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if got := readESCollectorStatus(link, 42, now); got != nil {
		t.Fatal("status reader followed a symlink")
	}
}
