package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestFlagEvidenceKeepsNewestInstant(t *testing.T) {
	for _, tc := range []struct{ name, older, newer string }{
		{"nanoseconds", "2026-10-11T12:00:00.100000001Z", "2026-10-11T12:00:00.100000002Z"},
		{"fraction width", "2026-10-11T12:00:00Z", "2026-10-11T12:00:00.000000001Z"},
		{"offsets", "2026-10-11T13:00:00.900000001+01:00", "2026-10-11T08:00:00.900000002-04:00"},
		{"second boundary", "2026-10-11T12:00:00.999999999Z", "2026-10-11T12:00:01Z"},
		{"equal instant", "2026-10-11T13:00:00+01:00", "2026-10-11T12:00:00.000000000Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "e.db")
			s, err := Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for _, row := range []struct{ id, ts string }{{"a-older", tc.older}, {"z-newer", tc.newer}} {
				at, err := time.Parse(time.RFC3339Nano, row.ts)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.PutFlag(model.Flag{ID: row.id, Rule: "r", Agent: "codex", SessionID: "owned", Severity: 2, TS: at}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec("UPDATE flags SET ts=? WHERE id=?", row.ts, row.id); err != nil {
					t.Fatal(err)
				}
			}
			for _, filter := range []FlagFilter{{Limit: 1}, {Limit: 2}, {Rule: "r", Agent: "codex", SessionID: "owned", MinSeverity: 2, Unacted: true, Limit: 1}} {
				got, err := s.QueryFlagsResult(filter)
				if err != nil || len(got) != filter.Limit || got[0].ID != "z-newer" {
					t.Fatalf("flag limit %+v: flags=%+v err=%v", filter, got, err)
				}
			}
			if _, err := s.db.Exec(trimFlagsSQL, 2); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := s.db.QueryRow("SELECT COUNT(*) FROM flags").Scan(&count); err != nil || count != 2 {
				t.Fatalf("at cap: count=%d err=%v", count, err)
			}
			if _, err := s.db.Exec(trimFlagsSQL, 1); err != nil {
				t.Fatal(err)
			}
			s.Close()
			s, err = Open(path, "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, err := s.QueryFlagsResult(FlagFilter{Limit: 2})
			if err != nil || len(got) != 1 || got[0].ID != "z-newer" {
				t.Fatalf("retained flag after reopen: flags=%+v err=%v", got, err)
			}
		})
	}
}

func TestFlagEvidenceMigratesTimeIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec("DROP INDEX IF EXISTS idx_flags_instant_time; CREATE INDEX IF NOT EXISTS idx_flags_time ON flags(datetime(ts), ts)"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var legacy int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_flags_time'").Scan(&legacy); err != nil || legacy != 0 {
		t.Fatalf("obsolete index retained: count=%d err=%v", legacy, err)
	}
	q, args := flagQuery(FlagFilter{Limit: 1})
	for _, plan := range []string{queryPlan(t, s, trimFlagsSQL, 1), queryPlan(t, s, q, args...)} {
		if !strings.Contains(plan, "idx_flags_instant_time") || strings.Contains(plan, "TEMP B-TREE") {
			t.Fatalf("flag query sorts instead of using instant index: %s", plan)
		}
	}
}
