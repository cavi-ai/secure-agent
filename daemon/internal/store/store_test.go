package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestPutAndReadFlagRoundTrips(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.PutFlag(model.Flag{ID: "f1", Rule: "r", Severity: 3, PID: 7, Agent: "cursor"})
	got := s.RecentFlags(10)
	if len(got) != 1 || got[0].ID != "f1" {
		t.Fatalf("RecentFlags = %+v", got)
	}
}

func TestPutFlagAlsoAppendsJSONL(t *testing.T) {
	dir := t.TempDir()
	jl := filepath.Join(dir, "e.jsonl")
	s, _ := Open(filepath.Join(dir, "e.db"), jl)
	s.PutFlag(model.Flag{ID: "f1", Rule: "r", Severity: 1})
	s.Close()
	b, _ := os.ReadFile(jl)
	if !strings.Contains(string(b), `"f1"`) {
		t.Fatal("flag not mirrored to JSONL")
	}
}

func TestEventRetentionBatchPruning(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 2500; i++ {
		s.PutEvent(event.Event{Kind: event.KindExec, PID: int32(i)})
	}

	s.PruneEvents(100)
	eventsAfterPrune := s.RecentEvents(2000)
	if len(eventsAfterPrune) != 100 {
		t.Fatalf("events count after explicit prune = %d, want 100", len(eventsAfterPrune))
	}
}
