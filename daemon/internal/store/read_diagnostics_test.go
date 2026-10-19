package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadDiagnosticsRetainSafeCauseAfterRecovery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := time.Now().UTC()
	s.noteRead("session report events", fmt.Errorf("private query and value: %w", context.DeadlineExceeded))
	s.noteRead("session report events", fmt.Errorf("private query and value: %w", context.DeadlineExceeded))
	s.noteRead("session report events", nil)
	data, err := json.Marshal(s.WriteHealth())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private query") {
		t.Fatal("read diagnostics leaked error text")
	}
	var health struct {
		ReadIssues []struct {
			Operation      string     `json:"operation"`
			Category       string     `json:"category"`
			Failures       uint64     `json:"failures"`
			FirstFailureAt time.Time  `json:"first_failure_at"`
			LastFailureAt  time.Time  `json:"last_failure_at"`
			RecoveredAt    *time.Time `json:"recovered_at"`
		} `json:"read_issues"`
	}
	if err := json.Unmarshal(data, &health); err != nil {
		t.Fatal(err)
	}
	if len(health.ReadIssues) != 1 {
		t.Fatalf("missing retained read diagnostic: %s", data)
	}
	issue := health.ReadIssues[0]
	if issue.Operation != "session report events" || issue.Category != "deadline" || issue.Failures != 2 || issue.FirstFailureAt.Before(before) || issue.LastFailureAt.Before(issue.FirstFailureAt) || issue.RecoveredAt == nil || issue.RecoveredAt.Before(issue.LastFailureAt) {
		t.Fatalf("invalid read diagnostic: %s", data)
	}
	if len(s.WriteHealth().ReadActive) != 0 {
		t.Fatal("recovered read remains active")
	}
}

func TestReportReadFailureRecordsClosedDatabase(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := s.sessionEventsOldestFirst("session"); err == nil {
		t.Fatal("closed database accepted report query")
	}
	data, err := json.Marshal(s.WriteHealth())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"category":"closed"`) || !strings.Contains(string(data), `"operation":"session report events"`) {
		t.Fatalf("report failure cause missing: %s", data)
	}
}
