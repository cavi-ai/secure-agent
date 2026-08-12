package collect

import (
	"bytes"
	"os"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestParseOpenLine(t *testing.T) {
	line, err := os.ReadFile("testdata/open.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	first := bytes.SplitN(line, []byte("\n"), 2)[0]
	e, ok := ParseESLine(first)
	if !ok || e.Kind != event.KindFileOpen {
		t.Fatalf("ParseESLine kind = %v, ok = %v; want KindFileOpen, true", e.Kind, ok)
	}
	if e.Path != "/Users/x/proj/.env" || e.PID != 1234 {
		t.Fatalf("missing or wrong path/pid: %+v", e)
	}
}
