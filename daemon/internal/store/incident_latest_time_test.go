package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentAggregationPreservesLatestEvidenceTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first := time.Date(2026, 10, 9, 12, 0, 0, 123456789, time.UTC)
	if err := s.PutIncident(model.IncidentReport{ID: "incident", FlagID: "first", Timestamp: first}); err != nil {
		t.Fatal(err)
	}
	latest := first.Add(time.Minute)
	for i, tc := range []struct {
		flagID   string
		at, want time.Time
	}{
		{"before original", first.Add(-time.Minute), first},
		{"newest", latest, latest},
		{"delayed", first.Add(time.Second), latest},
		{"same instant", latest.In(time.FixedZone("offset", 2*60*60)), latest},
		{"one nanosecond newer", latest.Add(time.Nanosecond), latest.Add(time.Nanosecond)},
	} {
		report, ok := s.AggregateIntoIncident("incident", tc.flagID, tc.at)
		if !ok || report.AggregateCount != i+2 || report.LastFlagAt == nil || !report.LastFlagAt.Equal(tc.want) {
			t.Fatalf("%s: delta=%+v ok=%v want count=%d time=%s", tc.flagID, report, ok, i+2, tc.want)
		}
		stored, err := s.GetIncident("incident")
		if err != nil || stored.AggregateCount != i+2 || stored.LastFlagAt == nil || !stored.LastFlagAt.Equal(tc.want) {
			t.Fatalf("%s: saved report=%+v err=%v", tc.flagID, stored, err)
		}
		var rawTime string
		if err := s.db.QueryRow(`SELECT last_flag_at FROM incidents WHERE id='incident'`).Scan(&rawTime); err != nil {
			t.Fatal(err)
		}
		at, err := time.Parse(time.RFC3339Nano, rawTime)
		if err != nil || !at.Equal(tc.want) {
			t.Fatalf("%s: saved timestamp=%s err=%v", tc.flagID, rawTime, err)
		}
		if id, ok := s.IncidentIDForFlag(tc.flagID); !ok || id != "incident" {
			t.Fatalf("%s: evidence link missing", tc.flagID)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if report, err := reopened.GetIncident("incident"); err != nil || report.AggregateCount != 6 || report.LastFlagAt == nil || !report.LastFlagAt.Equal(latest.Add(time.Nanosecond)) {
		t.Fatalf("reopened incident=%+v err=%v", report, err)
	}
}
