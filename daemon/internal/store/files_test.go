package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func fileTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Evidence matching is exact: LIKE wildcards and quotes in a path never widen
// the match to another path.
func TestPathFindingsMatchExactly(t *testing.T) {
	s := fileTestStore(t)
	odd := `/w/a%b_c'd"e.txt`
	near := `/w/aXbYc'd"e.txt`
	now := time.Now()
	s.PutFlag(model.Flag{ID: "f-odd", Rule: "secret-in-transcript", Severity: 3, TS: now, Agent: "codex", SessionID: "s1",
		Evidence: []model.EvidenceItem{{Kind: "transcript", Label: odd, Rule: "fp-1", Offset: 10}}})
	s.PutFlag(model.Flag{ID: "f-near", Rule: "secret-in-transcript", Severity: 3, TS: now, Agent: "codex",
		Evidence: []model.EvidenceItem{{Kind: "transcript", Label: near, Rule: "fp-1"}}})
	s.PutIncident(model.IncidentReport{ID: "inc-odd", FlagID: "f-odd", Rule: "secret-in-transcript", Risk: "high",
		Timestamp: now, TouchedFiles: []string{odd}, Connections: []string{}, RotateList: []model.RotateItem{}})
	s.PutIncident(model.IncidentReport{ID: "inc-near", FlagID: "f-near", Rule: "secret-in-transcript", Risk: "high",
		Timestamp: now, TouchedFiles: []string{near + ".bak"}, Connections: []string{}, RotateList: []model.RotateItem{}})

	got := s.PathFindings(odd, 20)
	if len(got) != 2 {
		t.Fatalf("findings for %q = %+v, want the one flag and the one incident", odd, got)
	}
	kinds := map[string]string{}
	for _, f := range got {
		kinds[f.Kind] = f.ID
	}
	if kinds["flag"] != "f-odd" || kinds["incident"] != "inc-odd" {
		t.Fatalf("findings = %+v", got)
	}
	for _, f := range got {
		if f.Kind == "flag" && (f.EvidenceKind != "transcript" || f.EvidenceRule != "fp-1" || f.Offset != 10) {
			t.Fatalf("flag finding evidence = %+v, want transcript fp-1 at 10", f)
		}
	}
	if got := s.PathFindings("/w/none.txt", 20); got == nil || len(got) != 0 {
		t.Fatalf("no evidence: got %#v, want empty non-nil", got)
	}
}

// Accesses are agent-session file events on the path only.
func TestPathAccessesAreSessionFileEvents(t *testing.T) {
	s := fileTestStore(t)
	p := "/w/project/.env"
	now := time.Now()
	s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now, PID: 10, ExePath: "/bin/cat", Path: p, SessionID: "s1"})
	s.PutEvent(event.Event{Kind: event.KindFileWrite, TS: now.Add(time.Second), PID: 11, Path: p, SessionID: "s1"})
	s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now, PID: 12, Path: p})                        // no session
	s.PutEvent(event.Event{Kind: event.KindExec, TS: now, PID: 13, Path: p, SessionID: "s1"})           // not a file event
	s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now, PID: 14, Path: p + "x", SessionID: "s1"}) // other path

	got := s.PathAccesses(p, 20)
	if len(got) != 2 || got[0].PID != 11 || got[0].Kind != "file-write" || got[1].PID != 10 || got[1].ExePath != "/bin/cat" {
		t.Fatalf("accesses = %+v, want pid 11 write then pid 10 open", got)
	}
	if got := s.PathAccesses("/w/none", 20); got == nil || len(got) != 0 {
		t.Fatalf("no accesses: got %#v, want empty non-nil", got)
	}
}

func TestPathReadResultsDiscardPartialRowsAndRecover(t *testing.T) {
	for _, operation := range []string{"path findings", "path accesses"} {
		t.Run(operation, func(t *testing.T) {
			s := fileTestStore(t)
			p := "/w/test.txt"
			now := time.Now()
			if _, err := s.PutFlag(model.Flag{ID: "f1", TS: now, Evidence: []model.EvidenceItem{{Label: p}}}); err != nil {
				t.Fatal(err)
			}
			inc := model.IncidentReport{ID: "i1", Timestamp: now, TouchedFiles: []string{p}}
			if err := s.PutIncident(inc); err != nil {
				t.Fatal(err)
			}
			var savedReport string
			if err := s.db.QueryRow("SELECT report_json FROM incidents WHERE id='i1'").Scan(&savedReport); err != nil {
				t.Fatal(err)
			}
			for _, pid := range []int32{1, 2} {
				if _, err := s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: now, PID: pid, Path: p, SessionID: "s1"}); err != nil {
					t.Fatal(err)
				}
			}
			read := func() (int, bool, error) {
				if operation == "path findings" {
					got, err := s.PathFindingsResult(p, 20)
					return len(got), got == nil, err
				}
				got, err := s.PathAccessesResult(p, 20)
				return len(got), got == nil, err
			}
			damage := "UPDATE incidents SET report_json='invalid /w/test.txt'"
			if operation == "path accesses" {
				damage = "UPDATE events SET pid='invalid' WHERE pid=1"
			}
			if _, err := s.db.Exec(damage); err != nil {
				t.Fatal(err)
			}
			if count, isNil, err := read(); err == nil || count != 0 || !isNil {
				t.Fatalf("partial result: count=%d nil=%v err=%v", count, isNil, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{operation}) || h.Failures != 0 {
				t.Fatalf("read failure health: %+v", h)
			}
			if _, err := s.db.Exec("UPDATE incidents SET report_json=? WHERE id='i1'", savedReport); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE events SET pid=1 WHERE pid='invalid'"); err != nil {
				t.Fatal(err)
			}
			if count, isNil, err := read(); err != nil || count != 2 || isNil {
				t.Fatalf("recovered result: count=%d nil=%v err=%v", count, isNil, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Fatalf("recovery health: %+v", h)
			}
			s.Close()
			if count, isNil, err := read(); err == nil || count != 0 || !isNil {
				t.Fatalf("unavailable result: count=%d nil=%v err=%v", count, isNil, err)
			}
		})
	}
}
