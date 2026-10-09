package store

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestSessionReportResultRejectsPartialEvidenceAndRecovers(t *testing.T) {
	for _, tc := range []struct{ name, damage, repair string }{
		{"event scan", `UPDATE events SET duration_ms='invalid' WHERE tool='Bash'`, `UPDATE events SET duration_ms=0`},
		{"event timestamp", `UPDATE events SET ts='invalid' WHERE tool='Bash'`, ""},
		{"event cost", `UPDATE events SET cost_usd='Inf' WHERE tool='Bash'`, `UPDATE events SET cost_usd=0`},
		{"cost overflow", `UPDATE events SET cost_usd=1e308 WHERE session_id='s1'`, `UPDATE events SET cost_usd=0`},
		{"event query", `ALTER TABLE events RENAME TO unavailable_events`, `ALTER TABLE unavailable_events RENAME TO events`},
		{"flag", `UPDATE flags SET evidence='invalid' WHERE id='f1'`, `UPDATE flags SET evidence=NULL WHERE id='f1'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			s := seedReportStore(t, now)
			if _, err := s.db.Exec(tc.damage); err != nil {
				t.Fatal(err)
			}
			rep, found, err := s.SessionReportResult("s1")
			if err == nil || found || !reflect.DeepEqual(rep, SessionReport{}) {
				t.Fatalf("partial report: %+v, %v, %v", rep, found, err)
			}
			h := s.WriteHealth()
			if !slices.Contains(h.ReadActive, "session reports") || h.ReadFailures == 0 || h.Failures != 0 {
				t.Fatalf("report fault health: %+v", h)
			}
			failures := h.ReadFailures
			if tc.repair != "" {
				if _, err := s.db.Exec(tc.repair); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.db.Exec("UPDATE events SET ts=? WHERE tool='Bash'", now.Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			if rep, found, err := s.SessionReportResult("s1"); err != nil || !found || rep.Events != 15 {
				t.Fatalf("recovered report: %+v, %v, %v", rep, found, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != failures || len(h.ReadActive) != 0 {
				t.Fatalf("recovered health: %+v", h)
			}
		})
	}
}

func TestSessionReportResultPreservesOptionalAvailability(t *testing.T) {
	s := seedReportStore(t, time.Now())
	for _, table := range []string{"interventions", "incidents"} {
		if _, err := s.db.Exec("ALTER TABLE " + table + " RENAME TO unavailable_" + table); err != nil {
			t.Fatal(err)
		}
	}
	rep, found, err := s.SessionReportResult("s1")
	if err != nil || !found || rep.Events != 15 || rep.IncidentsAvailable || rep.InterventionsAvailable {
		t.Fatalf("optional availability: %+v, %v, %v", rep, found, err)
	}
}

func TestSessionReportResultMissingClosedAndNullableEvents(t *testing.T) {
	s := seedReportStore(t, time.Now())
	if rep, found, err := s.SessionReportResult("missing"); err != nil || found || !reflect.DeepEqual(rep, SessionReport{}) {
		t.Fatalf("healthy missing: %+v, %v, %v", rep, found, err)
	}
	if _, err := s.db.Exec(`UPDATE events SET path=NULL, remote_host=NULL, detail=NULL, tool=NULL, tool_status=NULL, model=NULL, duration_ms=NULL, tokens_in=NULL, tokens_out=NULL, cost_usd=NULL`); err != nil {
		t.Fatal(err)
	}
	if rep, found, err := s.SessionReportResult("s1"); err != nil || !found || rep.Events != 15 {
		t.Fatalf("nullable event fields: %+v, %v, %v", rep, found, err)
	}
	s.Close()
	if rep, found, err := s.SessionReportResult("missing"); err == nil || found || !reflect.DeepEqual(rep, SessionReport{}) {
		t.Fatalf("unavailable report: %+v, %v, %v", rep, found, err)
	}
	if h := s.WriteHealth(); !slices.Contains(h.ReadActive, "session reports") {
		t.Fatalf("closed read health: %+v", h)
	}
}

func TestCheckedSessionReadsRejectInvalidTimestamps(t *testing.T) {
	for _, column := range []string{"started_at", "last_seen_at", "ended_at"} {
		t.Run(column, func(t *testing.T) {
			now := time.Now().UTC()
			s := seedReportStore(t, now)
			if _, err := s.db.Exec("UPDATE sessions SET " + column + "='invalid' WHERE id='s1'"); err != nil {
				t.Fatal(err)
			}
			if sess, found, err := s.GetSessionResult("s1"); err == nil || found || sess.ID != "" {
				t.Fatalf("invalid session identity: %+v, %v, %v", sess, found, err)
			}
			if sessions, err := s.ListSessionsResult(SessionFilter{Limit: 100}); err == nil || sessions != nil {
				t.Fatalf("partial session list: %+v, %v", sessions, err)
			}
			if _, found, err := s.SessionReportResult("s1"); err == nil || found {
				t.Fatalf("invalid report identity: found=%v err=%v", found, err)
			}
			if _, err := s.db.Exec("UPDATE sessions SET "+column+"=? WHERE id='s1'", now.Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			if _, found, err := s.SessionReportResult("s1"); err != nil || !found {
				t.Fatalf("recovered identity: found=%v err=%v", found, err)
			}
			if _, err := s.ListSessionsResult(SessionFilter{Limit: 100}); err != nil {
				t.Fatal(err)
			}
			if h := s.WriteHealth(); len(h.ReadActive) != 0 {
				t.Fatalf("recovered identity health: %+v", h)
			}
		})
	}
}
