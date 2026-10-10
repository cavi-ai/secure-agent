package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestOpenIncidentLookupDistinguishesMissingFromUnavailable(t *testing.T) {
	for _, tc := range []struct{ name, fault, repair string }{
		{"scan", `UPDATE incidents SET id=NULL`, `UPDATE incidents SET id='incident'`},
		{"empty identity", `UPDATE incidents SET id=''`, `UPDATE incidents SET id='incident'`},
		{"query", `ALTER TABLE incidents RENAME TO unavailable_incidents`, `ALTER TABLE unavailable_incidents RENAME TO incidents`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if id, found, err := s.FindOpenIncidentResult("rule", "session", "subject"); err != nil || found || id != "" {
				t.Fatalf("missing incident: %q %v %v", id, found, err)
			}
			if err := s.PutIncident(model.IncidentReport{ID: "incident", Rule: "rule", SessionID: "session", Subject: "subject", Timestamp: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(tc.fault); err != nil {
				t.Fatal(err)
			}
			if id, found, err := s.FindOpenIncidentResult("rule", "session", "subject"); err == nil || found || id != "" {
				t.Fatalf("failed lookup reported a target or absence: %q %v %v", id, found, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 1 || h.ReadActive[0] != "incident lookup" {
				t.Fatalf("lookup fault hidden: %+v", h)
			}
			if _, err := s.db.Exec(tc.repair); err != nil {
				t.Fatal(err)
			}
			if id, found, err := s.FindOpenIncidentResult("rule", "session", "subject"); err != nil || !found || id != "incident" {
				t.Fatalf("lookup did not recover: %q %v %v", id, found, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Fatalf("lookup recovery health: %+v", h)
			}
		})
	}
}

func TestOpenIncidentLookupAggregatesIntoNewestInstant(t *testing.T) {
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
				if err := s.PutIncident(model.IncidentReport{ID: row.id, FlagID: row.id + "-flag", Rule: "rule", SessionID: "session", Subject: "subject", Timestamp: at}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec("UPDATE incidents SET created_at=? WHERE id=?", row.ts, row.id); err != nil {
					t.Fatal(err)
				}
			}
			id, found, err := s.FindOpenIncidentResult("rule", "session", "subject")
			if err != nil || !found || id != "z-newer" {
				t.Fatalf("newest aggregation target: id=%q found=%v err=%v", id, found, err)
			}
			if report, ok := s.AggregateIntoIncident(id, "repeat", time.Now()); !ok || report.ID != "z-newer" || report.AggregateCount != 2 {
				t.Fatalf("repeat attached to wrong report: %+v ok=%v", report, ok)
			}
			if older, err := s.GetIncident("a-older"); err != nil || older.AggregateCount != 1 {
				t.Fatalf("older report changed: %+v err=%v", older, err)
			}
			if _, _, err := s.SetIncidentStatusResult("z-newer", "resolved", "reviewed"); err != nil {
				t.Fatal(err)
			}
			if id, found, err := s.FindOpenIncidentResult("rule", "session", "subject"); err != nil || !found || id != "a-older" {
				t.Fatalf("resolved target selected: id=%q found=%v err=%v", id, found, err)
			}
			for _, key := range [][3]string{{"other", "session", "subject"}, {"rule", "other", "subject"}, {"rule", "session", "other"}} {
				if id, found, err := s.FindOpenIncidentResult(key[0], key[1], key[2]); err != nil || found || id != "" {
					t.Fatalf("aggregation key escaped: key=%v id=%q found=%v err=%v", key, id, found, err)
				}
			}
		})
	}
}
