package store

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestFlagReadResultsDiscardPartialRowsAndRecover(t *testing.T) {
	for _, damage := range []string{"pid='invalid'", "ts='invalid'", "evidence='invalid'", "process='invalid'", "last_seen='invalid'"} {
		t.Run(damage, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for _, id := range []string{"bad", "good"} {
				if _, err := s.PutFlag(model.Flag{ID: id, Rule: "rule", TS: time.Now(), PID: 1}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec("UPDATE flags SET " + damage + " WHERE id='bad'"); err != nil {
				t.Fatal(err)
			}
			got, err := s.QueryFlagsResult(FlagFilter{})
			if err == nil || got != nil {
				t.Fatalf("partial flags returned: %+v, %v", got, err)
			}
			h := s.WriteHealth()
			if h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"flags"}) || h.Failures != 0 {
				t.Fatalf("read failure misclassified: %+v", h)
			}
			if _, err := s.db.Exec("UPDATE flags SET pid=1, ts=?, evidence=NULL, process=NULL, last_seen=NULL WHERE id='bad'", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			got, err = s.QueryFlagsResult(FlagFilter{})
			if err != nil || len(got) != 2 {
				t.Fatalf("read did not recover: %+v, %v", got, err)
			}
			h = s.WriteHealth()
			if h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Fatalf("recovery health: %+v", h)
			}
			got, err = s.QueryFlagsResult(FlagFilter{Agent: "empty"})
			if err != nil || got == nil || len(got) != 0 {
				t.Fatalf("healthy empty read: %+v, %v", got, err)
			}
		})
	}
}

func TestFlagReadQueryFailure(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	got, err := s.QueryFlagsResult(FlagFilter{})
	if err == nil || got != nil {
		t.Fatalf("closed database read: %+v, %v", got, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"flags"}) || h.Failures != 0 {
		t.Fatalf("query failure health: %+v", h)
	}
}

func TestFlagReadAcceptsLegacyNullableFields(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec("INSERT INTO flags (id,severity,ts,pid) VALUES ('legacy',3,?,1)", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	got, err := s.QueryFlagsResult(FlagFilter{})
	if err != nil || len(got) != 1 || got[0].ID != "legacy" || got[0].Process != nil || got[0].LastSeen != nil {
		t.Fatalf("nullable flag read: %+v, %v", got, err)
	}
	flag, found, err := s.GetFlagResult("legacy")
	if err != nil || !found || flag.ID != "legacy" || flag.Process != nil || flag.LastSeen != nil {
		t.Fatalf("nullable flag detail: %+v, %v, %v", flag, found, err)
	}
}

func TestGetFlagResultDistinguishesMissingAndUnavailable(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if flag, found, err := s.GetFlagResult("missing"); err != nil || found || flag.ID != "" {
		t.Fatalf("missing flag: %+v, %v, %v", flag, found, err)
	}
	s.Close()
	if flag, found, err := s.GetFlagResult("missing"); err == nil || found || flag.ID != "" {
		t.Fatalf("unavailable flag: %+v, %v, %v", flag, found, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"flag detail"}) {
		t.Fatalf("flag detail read health: %+v", h)
	}
}

func TestFlagCursorFailureDiscardsEarlierValidRows(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, id := range []string{"bad", "good"} {
		if _, err := s.PutFlag(model.Flag{ID: id, Rule: "rule", TS: time.Now(), PID: 1}); err != nil {
			t.Fatal(err)
		}
	}
	q, args := flagQuery(FlagFilter{})
	q = strings.Replace(q, " evidence,", " CASE WHEN id='bad' THEN json_extract('invalid','$') ELSE evidence END,", 1)
	// Walk rowid directly so SQLite fails during iteration, after a valid row,
	// instead of evaluating the expression while materializing a sort.
	q = strings.Replace(q, "ORDER BY datetime(ts) DESC, ts DESC", "ORDER BY rowid DESC", 1)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := scanFlagsResult(rows)
	if err == nil || got != nil {
		t.Fatalf("cursor failure returned partial flags: %+v, %v", got, err)
	}
}
