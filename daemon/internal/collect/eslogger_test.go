package collect

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestParseOpenLine(t *testing.T) {
	line := []byte(`{"process":{"audit_token":{"pid":1234}},"event":{"open":{"file":{"path":"/Users/x/proj/.env"}}}}`)
	e, ok := ParseESLine(line)
	if !ok || e.Kind != event.KindFileOpen {
		t.Fatalf("ParseESLine kind = %v, ok = %v; want KindFileOpen, true", e.Kind, ok)
	}
	if e.Path != "/Users/x/proj/.env" || e.PID != 1234 {
		t.Fatalf("missing or wrong path/pid: %+v", e)
	}
}

func TestParseESLineDropsOwnPid(t *testing.T) {
	line := func(pid int) []byte {
		return []byte(fmt.Sprintf(`{"process":{"audit_token":{"pid":%d}},"event":{"open":{"file":{"path":"/Users/x/proj/.env"}}}}`, pid))
	}
	if _, ok := ParseESLine(line(os.Getpid())); ok {
		t.Fatal("ParseESLine accepted an event from the daemon's own pid")
	}
	if _, ok := ParseESLine(line(os.Getpid() + 1)); !ok {
		t.Fatal("ParseESLine dropped an event from another pid")
	}
}

// countingUnmarshal swaps in for unmarshalES for the duration of the test
// and counts how many times ParseESLine actually reaches json.Unmarshal.
func countingUnmarshal(t *testing.T) *int {
	t.Helper()
	prev := unmarshalES
	calls := 0
	unmarshalES = func(data []byte, v any) error {
		calls++
		return prev(data, v)
	}
	t.Cleanup(func() { unmarshalES = prev })
	return &calls
}

func TestParseESLineFastRejectsShortLine(t *testing.T) {
	calls := countingUnmarshal(t)
	if _, ok := ParseESLine([]byte("xy")); ok {
		t.Fatal("2-byte line must not parse")
	}
	if _, ok := ParseESLine([]byte(`,"st_ino":1`)); ok {
		t.Fatal("fragment must not parse")
	}
	if *calls != 0 {
		t.Fatalf("fast-reject reached json.Unmarshal %d times for short/fragment lines, want 0", *calls)
	}
}

func TestParseESLineFastRejectsGarbageWithoutJSON(t *testing.T) {
	calls := countingUnmarshal(t)
	garbage := bytes.Repeat([]byte(","), 1<<20)
	start := time.Now()
	if _, ok := ParseESLine(garbage); ok {
		t.Fatal("1 MiB of commas must not parse")
	}
	if elapsed := time.Since(start); elapsed > time.Millisecond {
		t.Fatalf("fast-reject took %v for 1 MiB of garbage, want under 1ms", elapsed)
	}
	if *calls != 0 {
		t.Fatalf("fast-reject reached json.Unmarshal %d times for 1 MiB of garbage, want 0", *calls)
	}
}
