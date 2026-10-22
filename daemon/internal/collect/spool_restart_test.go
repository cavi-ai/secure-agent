package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
)

// A first run has no saved position and loses nothing. A restart whose saved
// position's file rotated away while the daemon was stopped counts both spool
// files on disk as lost: every byte in them was written after that position.
func TestRestartCountsSpoolRotatedPastSavedPosition(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "es-spool.jsonl")
	state := filepath.Join(dir, "spool-position.json")
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tailer := func() *SpoolTailer {
		tl := NewSpoolTailerAt(bus.New(8), spool)
		tl.StatePath = state
		return tl
	}

	first := strings.Repeat(`{"first":1}`+"\n", 10)
	write(spool, first)
	run := tailer()
	c := run.startCursor()
	if c.offset != int64(len(first)) || run.Stats().BytesLost != 0 {
		t.Fatalf("first run: offset %d, lost %d; want the spool's end and no loss", c.offset, run.Stats().BytesLost)
	}
	run.savePosition(c, true)

	// While the daemon is stopped the spool rotates twice.
	rotated := strings.Repeat(`{"rotated":2}`+"\n", 20)
	current := strings.Repeat(`{"current":3}`+"\n", 5)
	write(spool+".1", rotated)
	write(spool, current)
	restarted := tailer()
	c = restarted.startCursor()
	st := restarted.Stats()
	if want := uint64(len(rotated) + len(current)); st.BytesLost != want || st.LossCause != "restart" {
		t.Fatalf("restart: lost %d (%q), want %d (restart)", st.BytesLost, st.LossCause, want)
	}
	if c.offset != int64(len(current)) {
		t.Fatalf("restart offset = %d, want the spool's end %d", c.offset, len(current))
	}

	// A restart that finds its position resumes it and loses nothing.
	restarted.savePosition(c, true)
	resumed := tailer()
	if c := resumed.startCursor(); c.offset != int64(len(current)) || resumed.Stats().BytesLost != 0 {
		t.Fatalf("resume: offset %d, lost %d; want the saved offset and no loss", c.offset, resumed.Stats().BytesLost)
	}
}
