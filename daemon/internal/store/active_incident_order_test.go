package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestRecentIncidentsOrderByInstant(t *testing.T) {
	for _, tc := range []struct{ name, older, newer string }{
		{"nanoseconds", "2026-10-10T12:00:00.100000001Z", "2026-10-10T12:00:00.100000002Z"},
		{"fraction width", "2026-10-10T12:00:00Z", "2026-10-10T12:00:00.000000001Z"},
		{"offsets", "2026-10-10T13:00:00.900000001+01:00", "2026-10-10T08:00:00.900000002-04:00"},
		{"second boundary", "2026-10-10T12:00:00.999999999Z", "2026-10-10T12:00:01Z"},
		{"equal instant", "2026-10-10T12:00:00Z", "2026-10-10T13:00:00.000000000+01:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for _, row := range []struct{ id, ts string }{{"a-older", tc.older}, {"z-newer", tc.newer}} {
				at, err := time.Parse(time.RFC3339Nano, row.ts)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.PutIncident(model.IncidentReport{ID: row.id, Timestamp: at}); err != nil {
					t.Fatal(err)
				}
				// Exercise historical timestamp offsets and fractional widths.
				if _, err := s.db.Exec("UPDATE incidents SET created_at=? WHERE id=?", row.ts, row.id); err != nil {
					t.Fatal(err)
				}
			}
			for _, limit := range []int{1, 2} {
				got, err := s.RecentIncidentsResult(limit)
				if err != nil || len(got) != limit || got[0].ID != "z-newer" {
					t.Fatalf("limit %d: reports=%+v err=%v", limit, got, err)
				}
			}
			if _, _, err := s.SetIncidentStatusResult("z-newer", "resolved", "reviewed"); err != nil {
				t.Fatal(err)
			}
			got, err := s.RecentIncidentsResult(1)
			if err != nil || len(got) != 1 || got[0].ID != "a-older" {
				t.Fatalf("resolved report consumed active limit: reports=%+v err=%v", got, err)
			}
		})
	}
}
