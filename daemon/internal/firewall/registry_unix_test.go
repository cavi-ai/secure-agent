//go:build darwin || linux

package firewall

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRegisteredSourceRejectsSocket(t *testing.T) {
	// Use a short directory to stay within the Unix socket path limit.
	dir, err := os.MkdirTemp("/tmp", "sa-source-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "source.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// A socket cannot be opened as a regular file. Expect the policy error
	// from its type check even on platforms where open would itself fail.
	if err := ValidateRegisteredSource(path); err == nil || err.Error() != "must be a regular file" {
		t.Fatalf("socket validation returned %v", err)
	}
}

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
