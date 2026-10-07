package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// seedFlagsAtCap fills a fresh store with maxFlags attributed flags spread
// over 500 pids, the steady state of a long-running daemon: a newly tagged
// pid usually has no untagged flags to take over.
func seedFlagsAtCap(b *testing.B) (*Store, time.Time) {
	b.Helper()
	s, err := Open(filepath.Join(b.TempDir(), "e.db"), "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maxFlags; i++ {
		ts := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO flags (id, rule, severity, ts, pid, agent) VALUES (?, 'r', 2, ?, ?, 'claude')`,
			fmt.Sprintf("seed-%d", i), ts, i%500); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return s, base
}

func BenchmarkPutFlagAtCap(b *testing.B) {
	s, base := seedFlagsAtCap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.PutFlag(model.Flag{ID: fmt.Sprintf("bench-%d", i), Rule: "r", Severity: 2, PID: int32(i % 500),
			TS: base.Add(time.Duration(maxFlags+i) * time.Second)})
	}
}

func BenchmarkReattributeFlagsAtCap(b *testing.B) {
	s, base := seedFlagsAtCap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ReattributeFlags(int32(i%500), "claude", base)
	}
}

// seedIncidentsAtCap fills a fresh store with maxIncidents incidents over
// 200 sessions, each with a 4 KiB report.
func seedIncidentsAtCap(b *testing.B) (*Store, time.Time) {
	b.Helper()
	s, err := Open(filepath.Join(b.TempDir(), "e.db"), "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	report := `{"summary":"` + strings.Repeat("x", 4096) + `"}`
	for i := 0; i < maxIncidents; i++ {
		ts := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO incidents (id, flag_id, report_json, created_at, rule, session_id, subject) VALUES (?, ?, ?, ?, 'r', ?, 'subj')`,
			fmt.Sprintf("inc-%d", i), fmt.Sprintf("flag-%d", i), report, ts, fmt.Sprintf("s%d", i%200)); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return s, base
}

func BenchmarkPutIncidentAtCap(b *testing.B) {
	s, base := seedIncidentsAtCap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.PutIncident(model.IncidentReport{ID: fmt.Sprintf("bench-%d", i), FlagID: fmt.Sprintf("bf-%d", i),
			Timestamp: base.Add(time.Duration(maxIncidents+i) * time.Second)}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFindOpenIncidentAtCap(b *testing.B) {
	s, _ := seedIncidentsAtCap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.FindOpenIncident("r", fmt.Sprintf("s%d", i%200), "subj")
	}
}

func BenchmarkQueryFlagsAtCap(b *testing.B) {
	s, _ := seedFlagsAtCap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.QueryFlags(FlagFilter{Limit: 100})
	}
}
