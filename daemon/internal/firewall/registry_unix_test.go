//go:build darwin || linux

package firewall

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestIngestRejectsNamedPipe(t *testing.T) {
	source := filepath.Join(t.TempDir(), "fixture.fifo")
	if err := syscall.Mkfifo(source, 0o600); err != nil {
		t.Fatal(err)
	}
	// There is no writer: opening the pipe for a blocking read would stall.
	fps, err := Ingest([]string{source}, []byte("salt"))
	if err == nil || fps != nil {
		t.Fatalf("pipe ingestion returned %d fingerprints and error %v", len(fps), err)
	}
}
