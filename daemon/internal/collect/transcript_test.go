package collect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestScanLineTranscriptHit(t *testing.T) {
	line := "some log output with Bearer sk-secrettoken123 in it"
	e, ok := ScanLine(line)
	if !ok || e.Kind != event.KindTranscriptHit {
		t.Fatalf("ScanLine kind = %v, ok = %v; want KindTranscriptHit, true", e.Kind, ok)
	}
	if e.Detail != "bearer-token" {
		t.Fatalf("Detail = %q, want bearer-token", e.Detail)
	}
	if strings.Contains(e.Detail, "sk-secrettoken123") {
		t.Fatal("secret token leaked into event detail!")
	}
}

func TestScanLinePluginAction(t *testing.T) {
	line := `{"ts":"2026-08-12T19:55:00Z","tool":"Bash","command":"ls"}`
	e, ok := ScanLine(line)
	if !ok || e.Kind != event.KindPluginAction {
		t.Fatalf("ScanLine kind = %v, ok = %v; want KindPluginAction, true", e.Kind, ok)
	}
	if e.Detail != "Bash" {
		t.Fatalf("Detail = %q, want Bash", e.Detail)
	}
}

// TestScannerTailsActiveFile locks the split-cadence refactor: a recently
// modified file stays in the active set and lines appended after startup are
// captured, while pre-existing content seeded past on startup is not replayed.
func TestScannerTailsActiveFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.jsonl")

	// Pre-existing content must be seeded past, not replayed onto the bus.
	if err := os.WriteFile(logPath, []byte(`{"tool":"OldTool"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{filepath.Join(dir, "*.jsonl")})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)

	// Append after the scanner has started and seeded existing content to EOF.
	time.Sleep(250 * time.Millisecond)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"tool":"Bash","command":"whoami"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	select {
	case e := <-sub:
		if e.Kind != event.KindPluginAction || e.Detail != "Bash" {
			t.Fatalf("got kind=%v detail=%q, want KindPluginAction/Bash", e.Kind, e.Detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scanner did not publish the appended transcript line")
	}
}

func TestScanLineFakeCursorActivity(t *testing.T) {
	line := `{"file_path":"/tmp/foo/.env","pid":12345,"tool":"Read"}`
	e, ok := ScanLine(line)
	if !ok || e.Kind != event.KindPluginAction {
		t.Fatalf("ScanLine kind = %v, ok = %v; want KindPluginAction, true", e.Kind, ok)
	}
	if e.PID != 12345 {
		t.Fatalf("PID = %d, want 12345", e.PID)
	}
	if e.Path != "/tmp/foo/.env" {
		t.Fatalf("Path = %q, want /tmp/foo/.env", e.Path)
	}
}
