package correlate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// A burst of other plist writes does not push out the agent's latest one.
func TestLaunchWriterEvictsTheOldest(t *testing.T) {
	c := &Correlator{}
	start := time.Now()
	for i := 0; i < maxLaunchWriters+10; i++ {
		c.rememberLaunchWriterLocked(event.Event{Kind: event.KindFileWrite, PID: 500, TS: start.Add(time.Duration(i) * time.Millisecond),
			Path: fmt.Sprintf("/Users/x/Library/LaunchAgents/junk-%d.plist", i)}, "cursor")
	}
	real := "/Users/x/Library/LaunchAgents/com.example.real.plist"
	at := start.Add(time.Second)
	c.rememberLaunchWriterLocked(event.Event{Kind: event.KindFileWrite, PID: 501, TS: at, Path: real}, "cursor")
	if len(c.launchWriters) != maxLaunchWriters {
		t.Fatalf("writers = %d, want %d", len(c.launchWriters), maxLaunchWriters)
	}
	if w, ok := c.launchWriterLocked(event.Event{Kind: event.KindLaunchItemAdd, Path: real, TS: at.Add(time.Second)}); !ok || w.pid != 501 {
		t.Fatalf("latest write lost: %+v %v", w, ok)
	}
	if _, ok := c.launchWriters["/Users/x/Library/LaunchAgents/junk-0.plist"]; ok {
		t.Fatal("oldest entry kept")
	}
}

// A profile path the agent made a FIFO or a link is not read: the read runs
// under the correlator's lock.
func TestReadProfileFileOnlyReadsRegularFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "x.mobileconfig")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readProfileFile(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO read")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read blocked on a FIFO")
	}

	regular := filepath.Join(dir, "real.mobileconfig")
	if err := os.WriteFile(regular, []byte("<key>PayloadIdentifier</key><string>com.example.p</string>"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.mobileconfig")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProfileFile(link); err == nil {
		t.Fatal("followed a link")
	}
	if b, err := readProfileFile(regular); err != nil || len(profileNames(b)) != 1 {
		t.Fatalf("regular file: %q %v", b, err)
	}
}
