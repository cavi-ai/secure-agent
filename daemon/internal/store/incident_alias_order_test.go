package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentFlagAliasesSelectNewestInstant(t *testing.T) {
	for _, tc := range []struct{ name, older, newer string }{
		{"nanoseconds", "2026-10-09T12:00:00.100000001Z", "2026-10-09T12:00:00.100000002Z"},
		{"fraction width", "2026-10-09T12:00:00Z", "2026-10-09T12:00:00.000000001Z"},
		{"second boundary", "2026-10-09T12:00:00.999999999Z", "2026-10-09T12:00:01Z"},
		{"offsets", "2026-10-09T08:00:00.900000001-04:00", "2026-10-09T13:00:00.900000002+01:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for _, row := range []struct{ id, ts string }{{"z-older", tc.older}, {"a-newer", tc.newer}} {
				ts, err := time.Parse(time.RFC3339Nano, row.ts)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.PutIncident(model.IncidentReport{ID: row.id, FlagID: "first", Timestamp: ts}); err != nil {
					t.Fatal(err)
				}
				if _, ok := s.AggregateIntoIncident(row.id, "repeat", ts); !ok {
					t.Fatal("could not aggregate repeat flag")
				}
				// Retain legacy offsets and variable fractional widths in storage.
				if _, err := s.db.Exec(`UPDATE incidents SET created_at=? WHERE id=?`, row.ts, row.id); err != nil {
					t.Fatal(err)
				}
			}
			for _, alias := range []string{"first", "repeat"} {
				if id, ok := s.IncidentIDForFlag(alias); !ok || id != "a-newer" {
					t.Errorf("flag link %s: id=%q found=%v, want a-newer", alias, id, ok)
				}
				if report, err := s.GetIncident(alias); err != nil || report.ID != "a-newer" {
					t.Errorf("report alias %s: report=%+v err=%v, want a-newer", alias, report, err)
				}
			}
			if report, err := s.GetIncident("z-older"); err != nil || report.ID != "z-older" {
				t.Errorf("direct identity changed: report=%+v err=%v", report, err)
			}
		})
	}
}
