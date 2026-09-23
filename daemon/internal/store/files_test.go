package store

import (
	"path/filepath"
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
