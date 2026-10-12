package store

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCleanupLedgerAndAsksRejectUnavailableAndPartialReads(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	reads := map[string]struct {
		label string
		read  func(*Store) (int, bool, error)
	}{
		"log": {"cleanup log", func(s *Store) (int, bool, error) {
			rows, err := s.CleanupLog(10)
			return len(rows), rows == nil, err
		}},
		"totals": {"cleanup totals", func(s *Store) (int, bool, error) {
			t, err := s.CleanupTotals(now)
			return t.Count, t.Count == 0 && t.Bytes == 0, err
		}},
		"daily": {"cleanup daily", func(s *Store) (int, bool, error) {
			days, err := s.CleanupDaily(now, 3)
			return len(days), days == nil, err
		}},
		"asks": {"agent asks", func(s *Store) (int, bool, error) {
			asks, err := s.AgentAsks(10)
			return len(asks), asks == nil, err
		}},
	}
	for name, r := range reads {
		for _, fault := range []string{"empty", "closed", "scan", "time"} {
			if name == "totals" && (fault == "scan" || fault == "time") {
				continue
			}
			t.Run(name+"/"+fault, func(t *testing.T) {
				s, err := Open("", "")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.Close() })
				if fault == "closed" {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if fault == "scan" || fault == "time" {
					// A valid newest row precedes one that cannot be decoded: a value
					// of the wrong type, or a time the store never writes. The read
					// must discard the valid rows, not return them.
					badTS, badBytes, badCost := "2026-10-12T10:00:00Z", "5", "0.1"
					if fault == "time" {
						badTS = "2026-10-12T10:00:00.xZ"
					} else {
						badBytes, badCost = "'lots'", "'dear'"
					}
					query := `INSERT INTO cleanup_log(ts,action,path,bytes) VALUES
						('` + badTS + `','worktree-remove','/r/.worktrees/bad',` + badBytes + `),
						('2026-10-12T11:00:00Z','worktree-remove','/r/.worktrees/good',5)`
					if name == "asks" {
						query = `INSERT INTO agent_asks(ts,path,harness,session_id,status,cost_usd) VALUES
							('` + badTS + `','/r/.worktrees/bad','claude','s','answered',` + badCost + `),
							('2026-10-12T11:00:00Z','/r/.worktrees/good','claude','s','answered',0.1)`
					}
					if _, err := s.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
				count, empty, err := r.read(s)
				if fault == "empty" {
					want := 0
					if name == "daily" {
						want = 3
					}
					if err != nil || count != want || (name != "daily" && name != "totals" && empty) {
						t.Fatalf("empty read: count=%d nil=%v err=%v", count, empty, err)
					}
					return
				}
				if err == nil || !empty || count != 0 {
					t.Fatalf("failed read returned values: count=%d err=%v", count, err)
				}
				if want := map[string]string{"scan": "scan", "time": "parse"}[fault]; want != "" && !strings.Contains(err.Error(), want) {
					t.Fatalf("%s error lost: %v", fault, err)
				}
				if !slices.Contains(s.WriteHealth().ReadActive, r.label) {
					t.Fatalf("read health = %+v, want %q", s.WriteHealth().ReadActive, r.label)
				}
				if fault == "closed" {
					return
				}
				for _, q := range []string{`DELETE FROM cleanup_log WHERE path LIKE '%/bad'`, `DELETE FROM agent_asks WHERE path LIKE '%/bad'`} {
					if _, err := s.db.Exec(q); err != nil {
						t.Fatal(err)
					}
				}
				if count, _, err := r.read(s); err != nil || count == 0 || slices.Contains(s.WriteHealth().ReadActive, r.label) {
					t.Fatalf("repaired read: count=%d err=%v health=%+v", count, err, s.WriteHealth().ReadActive)
				}
			})
		}
	}
}

func TestCleanupReadSuccessKeepsOtherLedgerFaults(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.Exec(`INSERT INTO cleanup_log(ts,action,path,bytes) VALUES ('2026-10-12T10:00:00Z','worktree-remove','/r/.worktrees/bad','lots')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CleanupLog(10); err == nil {
		t.Fatal("undecodable ledger row was returned")
	}
	if _, err := s.CleanupTotals(time.Now()); err != nil {
		t.Fatalf("totals: %v", err)
	}
	if got := s.WriteHealth().ReadActive; !slices.Contains(got, "cleanup log") || slices.Contains(got, "cleanup totals") {
		t.Fatalf("read health = %+v, want the log fault kept after totals succeeded", got)
	}
}
