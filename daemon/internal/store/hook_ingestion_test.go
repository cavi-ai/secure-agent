package store

import (
	"testing"
	"time"
)

func TestHookIngestionDiagnostics(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.HookIngestion().Available {
		t.Fatal("unwired collector reported available")
	}
	s.TrackHookIngestion()
	start := s.HookIngestion().Since
	s.NoteHookAccepted("codex")
	s.NoteHookAccepted("codex") // deliveries, including retries, not unique runs
	s.NoteHookAccepted("untrusted-harness")
	s.NoteHookRejected()
	s.TrackHookIngestion() // supervisor restarts retain process-local counters
	h := s.HookIngestion()
	if !h.Available || !h.Since.Equal(start) || h.Rejected != 1 || h.LastRejectedAt == nil || len(h.Harnesses) != 1 || h.Harnesses[0].Harness != "codex" || h.Harnesses[0].Accepted != 2 || h.Harnesses[0].LastReceivedAt.Before(start) || h.Harnesses[0].LastReceivedAt.After(time.Now()) {
		t.Fatalf("diagnostics = %+v", h)
	}
	h.Harnesses[0].Accepted = 900
	*h.LastRejectedAt = time.Time{}
	if got := s.HookIngestion(); got.Harnesses[0].Accepted != 2 || got.LastRejectedAt.IsZero() {
		t.Fatal("snapshot aliases live state")
	}
}
