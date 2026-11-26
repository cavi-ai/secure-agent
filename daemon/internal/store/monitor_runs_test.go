package store

import (
	"path/filepath"
	"testing"
	"time"
)

// A run's stop intent is stored per pid and start time and read back; a run
// that is not stored is reported as not found.
func TestMonitorRunsKeepStopIntentPerRun(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if has, err := s.HasMonitorRuns(); err != nil || has {
		t.Fatalf("new store HasMonitorRuns = %v, %v; want false", has, err)
	}

	start := time.Date(2026, 11, 25, 9, 0, 0, 123456789, time.UTC)
	if err := s.PutMonitorRun(4242, start); err != nil {
		t.Fatal(err)
	}
	if at, found, err := s.MonitorRunStopIntent(4242, start); err != nil || !found || !at.IsZero() {
		t.Fatalf("run without intent = %v, %v, %v; want zero time, found", at, found, err)
	}
	if _, found, err := s.MonitorRunStopIntent(4242, start.Add(time.Second)); err != nil || found {
		t.Fatalf("other start time found = %v, %v; want not found", found, err)
	}

	intent := start.Add(time.Hour)
	if err := s.PutMonitorStopIntent(4242, start, intent); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMonitorRun(4242, start); err != nil {
		t.Fatal(err)
	}
	if at, found, err := s.MonitorRunStopIntent(4242, start); err != nil || !found || !at.Equal(intent) {
		t.Fatalf("stored intent = %v, %v, %v; want %v", at, found, err, intent)
	}
	if has, err := s.HasMonitorRuns(); err != nil || !has {
		t.Fatalf("HasMonitorRuns = %v, %v; want true", has, err)
	}
}

// The table keeps the most recent maxMonitorRuns runs.
func TestMonitorRunsDropTheOldestPastTheBound(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	start := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	for i := 0; i <= maxMonitorRuns; i++ {
		if err := s.PutMonitorRun(1000+i, start.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := s.MonitorRunStopIntent(1000, start); err != nil || found {
		t.Fatalf("oldest run found = %v, %v; want dropped", found, err)
	}
	last := start.Add(time.Duration(maxMonitorRuns) * time.Minute)
	if _, found, err := s.MonitorRunStopIntent(1000+maxMonitorRuns, last); err != nil || !found {
		t.Fatalf("newest run found = %v, %v; want kept", found, err)
	}
}
