package collect

import (
	"fmt"
	"os"
	"testing"

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
