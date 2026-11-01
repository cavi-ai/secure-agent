package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// firstTranscriptEvent runs a scanner on target with a checkpoint saved at savedAt
// and returns the first event it publishes, or false within wait.
func firstTranscriptEvent(t *testing.T, target string, savedAt time.Time, wait time.Duration) (event.Event, bool) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "offsets.json")
	if err := os.WriteFile(state, []byte(`{"version":1,"offsets":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(state, savedAt, savedAt); err != nil {
		t.Fatal(err)
	}
	b := bus.New(16)
	defer b.Close()
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{target})
	ts.OffsetStatePath = state
	ts.tailEvery = 10 * time.Millisecond
	ts.resolveEvery = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = ts.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case e := <-sub:
		return e, true
	case <-time.After(wait):
		return event.Event{}, false
	}
}

// A transcript created while the daemon was down, after its checkpoint was
// saved, is read from its first line.
func TestTranscriptCreatedWhileDownIsReadWhole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	if err := os.WriteFile(path, []byte(`{"tool":"Read"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if e, ok := firstTranscriptEvent(t, path, time.Now().Add(-time.Hour), 3*time.Second); !ok || e.Detail != "Read" {
		t.Fatalf("first line of a file created after the checkpoint: %+v, %v", e, ok)
	}
}

// A file that existed before the checkpoint was saved is seeded past its
// content, as on any first sighting: history is not replayed.
func TestTranscriptOlderThanCheckpointIsNotReplayed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	if err := os.WriteFile(path, []byte(`{"tool":"Read"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if e, ok := firstTranscriptEvent(t, path, time.Now().Add(time.Hour), 300*time.Millisecond); ok {
		t.Fatalf("replayed a file older than the checkpoint: %+v", e)
	}
}
