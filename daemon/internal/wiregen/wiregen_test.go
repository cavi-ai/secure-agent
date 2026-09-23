package wiregen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWireTypesDrift pins the committed .d.ts to the Go structs. If this
// fails, run: go run ./cmd/genwire (from daemon/).
func TestWireTypesDrift(t *testing.T) {
	path := filepath.Join("..", "..", "..", "daemon", "internal", "api", "web_dist", "wire-types.d.ts")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join("..", "api", "web_dist", "wire-types.d.ts")
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if Generate() != string(committed) {
		t.Fatalf("wire-types.d.ts is stale — regenerate with: go run ./cmd/genwire (from daemon/)")
	}
}

// A json:"-" field is off the wire: neither the field nor its struct type is
// emitted.
func TestTypeScriptSkipsHiddenFieldTypes(t *testing.T) {
	type hidden struct{ X int }
	type wire struct {
		A string   `json:"a"`
		H []hidden `json:"-"`
	}
	ts := TypeScript(wire{})
	if strings.Contains(ts, "hidden") || strings.Contains(ts, "H:") {
		t.Fatalf("json:\"-\" field or its type emitted:\n%s", ts)
	}
	if !strings.Contains(ts, "a: string;") {
		t.Fatalf("wire field missing:\n%s", ts)
	}
}
