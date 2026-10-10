package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentCountPersistsConsistently(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count, want int
	}{{"default", 0, 1}, {"explicit", 3, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "incidents.db")
			s, err := Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			now := time.Now()
			if err := s.PutIncident(model.IncidentReport{ID: "incident", FlagID: "first", Timestamp: now, AggregateCount: tc.count}); err != nil {
				t.Fatal(err)
			}
			check := func(s *Store, want int) {
				t.Helper()
				var count int
				if err := s.db.QueryRow(`SELECT aggregate_count FROM incidents WHERE id='incident'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != want {
					t.Errorf("stored count=%d, want %d", count, want)
				}
				if report, err := s.GetIncident("incident"); err != nil || report.AggregateCount != want {
					t.Errorf("stored report=%+v err=%v, want count %d", report, err, want)
				}
			}
			check(s, tc.want)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			check(reopened, tc.want)
			if report, ok := reopened.AggregateIntoIncident("incident", "second", now.Add(time.Second)); !ok || report.AggregateCount != tc.want+1 {
				t.Fatalf("aggregation after reopening: report=%+v ok=%v", report, ok)
			}
			check(reopened, tc.want+1)
		})
	}
}
