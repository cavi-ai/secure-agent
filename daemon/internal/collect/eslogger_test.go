package collect

import (
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
