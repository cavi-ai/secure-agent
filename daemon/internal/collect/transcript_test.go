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

// A line longer than the reader's buffer must still parse. Regression: lines
// over 4 KB were counted toward the offset and skipped — real prompt records
// run 10 KB+, so turn detection silently saw none of them.
func TestOverlongLineStillParses(t *testing.T) {
	dir := t.TempDir()
	projectsDir := filepath.Join(dir, ".claude", "projects")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(projectsDir, "session.jsonl")
	if err := os.WriteFile(logPath, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{logPath})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)

	// Append a 12 KB user-prompt record after the seed.
	time.Sleep(250 * time.Millisecond)
	long := strings.Repeat("x", 12000)
	line := `{"sessionId":"turn-long","type":"user","timestamp":"2026-09-20T17:44:53.118Z","message":{"content":"` + long + `"}}` + "\n"
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
	f.Close()

	for {
		select {
		case e := <-sub:
			if e.Kind == event.KindTurn {
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatal("overlong prompt line was skipped, no turn published")
		}
	}
}

// A prompt appended to a transcript that was IDLE past the active window must
// still produce a turn. Regression: the resolve tick re-seeded every file's
// offset to EOF, so the appended line — the one that made the file active
// again — was skipped, and the prompt never became a turn.
func TestIdleFileAppendIsNotSkipped(t *testing.T) {
	dir := t.TempDir()
	projectsDir := filepath.Join(dir, ".claude", "projects")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(projectsDir, "session.jsonl")
	seedLine := `{"sessionId":"idle-s","type":"user","timestamp":"2026-09-20T17:44:53.118Z","isMeta":true,"message":{"content":"meta"}}` + "\n"
	if err := os.WriteFile(logPath, []byte(seedLine), 0o644); err != nil {
		t.Fatal(err)
	}

	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{projectsDir})
	ts.tailEvery = 20 * time.Millisecond
	ts.resolveEvery = 50 * time.Millisecond
	ts.activeWindowD = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)

	// Let the scanner seed the file, then age it out of the active set.
	time.Sleep(200 * time.Millisecond)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(logPath, old, old); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // a resolve tick with the file inactive

	// The append that ends the idle gap: a real prompt record.
	line := `{"sessionId":"idle-s","type":"user","timestamp":"2026-09-20T17:45:53.118Z","message":{"content":"fix the thing"}}` + "\n"
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
	f.Close()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-sub:
			if e.Kind == event.KindTurn && e.SessionID == "idle-s" {
				return
			}
		case <-deadline:
			t.Fatal("prompt appended after an idle gap was skipped — no turn published")
		}
	}
}

// A transcript created AFTER the scanner started is read from byte 0 — its
// whole content is new, so the first prompt must land.
func TestNewSessionFileReadFromStart(t *testing.T) {
	dir := t.TempDir()
	projectsDir := filepath.Join(dir, ".claude", "projects")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	b := bus.New(16)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{projectsDir})
	ts.tailEvery = 20 * time.Millisecond
	ts.resolveEvery = 50 * time.Millisecond
	ts.activeWindowD = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)
	time.Sleep(200 * time.Millisecond)

	logPath := filepath.Join(projectsDir, "brand-new.jsonl")
	line := `{"sessionId":"new-s","type":"user","timestamp":"2026-09-20T17:46:53.118Z","message":{"content":"first prompt"}}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-sub:
			if e.Kind == event.KindTurn && e.SessionID == "new-s" {
				return
			}
		case <-deadline:
			t.Fatal("new session transcript was not read from byte 0")
		}
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

func TestParseHandshake(t *testing.T) {
	line := `{"type":"session_start","ts":"2026-09-17T12:00:00Z","session_id":"abc","harness":"claude","workspace":"/repo","repo":"repo","branch":"main","pid":4242}`
	h, ok := ParseHandshake(line)
	if !ok {
		t.Fatal("handshake not recognized")
	}
	if h.SessionID != "abc" || h.Harness != "claude" || h.Workspace != "/repo" || h.Repo != "repo" || h.Branch != "main" || h.PID != 4242 {
		t.Fatalf("handshake = %+v", h)
	}

	// A regular activity line is not a handshake.
	if _, ok := ParseHandshake(`{"tool":"Read","pid":1,"session_id":"abc"}`); ok {
		t.Fatal("activity line misclassified as handshake")
	}
	// A handshake without a session id is useless — drop it.
	if _, ok := ParseHandshake(`{"type":"session_start","harness":"claude"}`); ok {
		t.Fatal("handshake without session_id must not parse")
	}
}

// Lines appended while the daemon is down must not be lost: with a persisted
// offset file the restarted scanner resumes where the last run stopped
// instead of re-seeding the transcript at EOF.
func TestOffsetsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.jsonl")
	statePath := filepath.Join(dir, "offsets.json")

	if err := os.WriteFile(logPath, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b1 := bus.New(16)
	sub1 := b1.Subscribe()
	ts1 := NewTranscriptScanner(b1, []string{logPath})
	ts1.OffsetStatePath = statePath
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan struct{})
	go func() { _ = ts1.Run(ctx1); close(done1) }()
	time.Sleep(250 * time.Millisecond)

	// Appended while "up": read and offset advanced.
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"tool":"Read","file_path":"/a"}` + "\n")
	f.Close()
	select {
	case <-sub1:
	case <-time.After(3 * time.Second):
		t.Fatal("first scanner did not publish the appended line")
	}
	// The dirty-save fires on the next tail tick after the offset advances.
	time.Sleep(500 * time.Millisecond)
	cancel1()
	select {
	case <-done1:
	case <-time.After(5 * time.Second):
		t.Fatal("first scanner did not stop after cancel")
	}

	// Appended while "down": the line a fresh-start seed would skip.
	f, _ = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"tool":"Bash","command":"ls"}` + "\n")
	f.Close()

	b2 := bus.New(16)
	sub2 := b2.Subscribe()
	ts2 := NewTranscriptScanner(b2, []string{logPath})
	ts2.OffsetStatePath = statePath
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { _ = ts2.Run(ctx2); close(done2) }()
	defer func() {
		cancel2()
		select {
		case <-done2:
		case <-time.After(5 * time.Second):
			t.Fatal("second scanner did not stop after cancel")
		}
	}()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case e := <-sub2:
			if e.Kind == event.KindPluginAction && e.Detail == "Bash" {
				return // the down-window line was picked up
			}
		case <-deadline:
			t.Fatal("line appended while the daemon was down was lost across restart")
		}
	}
}
