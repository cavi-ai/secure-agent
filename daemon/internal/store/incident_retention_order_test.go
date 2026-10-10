package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIncidentRetentionKeepsNewestInstant(t *testing.T) {
	for _, tc := range []struct{ name, older, newer string }{
		{"nanoseconds", "2026-10-10T12:00:00.100000001Z", "2026-10-10T12:00:00.100000002Z"},
		{"fraction width", "2026-10-10T12:00:00Z", "2026-10-10T12:00:00.000000001Z"},
		{"offsets", "2026-10-10T13:00:00.900000001+01:00", "2026-10-10T08:00:00.900000002-04:00"},
		{"second boundary", "2026-10-10T12:00:00.999999999Z", "2026-10-10T12:00:01Z"},
		{"equal instant", "2026-10-10T13:00:00+01:00", "2026-10-10T12:00:00.000000000Z"},
		{"invalid stamp", "garbage", "2026-10-10T12:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "e.db")
			s, err := Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for _, row := range []struct{ id, ts string }{{"a-older", tc.older}, {"z-newer", tc.newer}} {
				if _, err := s.db.Exec("INSERT INTO incidents (id, created_at) VALUES (?, ?)", row.id, row.ts); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec(trimIncidentsSQL, 2); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := s.db.QueryRow("SELECT COUNT(*) FROM incidents").Scan(&count); err != nil || count != 2 {
				t.Fatalf("at cap: count=%d err=%v", count, err)
			}
			if _, err := s.db.Exec(trimIncidentsSQL, 1); err != nil {
				t.Fatal(err)
			}
			s.Close()
			s, err = Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var id string
			if err := s.db.QueryRow("SELECT id FROM incidents").Scan(&id); err != nil || id != "z-newer" {
				t.Fatalf("retained report: id=%q err=%v", id, err)
			}
			if err := s.db.QueryRow("SELECT COUNT(*) FROM incidents").Scan(&count); err != nil || count != 1 {
				t.Fatalf("overflow trim: count=%d err=%v", count, err)
			}
		})
	}
}

func TestIncidentRetentionMigratesTimeIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP INDEX IF EXISTS idx_incidents_instant_time; CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(datetime(created_at), created_at)"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var legacy int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_incidents_time'").Scan(&legacy); err != nil || legacy != 0 {
		t.Fatalf("obsolete index retained: count=%d err=%v", legacy, err)
	}
	if plan := queryPlan(t, s, trimIncidentsSQL, 1); !strings.Contains(plan, "idx_incidents_instant_time") || strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("retention sorts instead of using instant index: %s", plan)
	}
}
