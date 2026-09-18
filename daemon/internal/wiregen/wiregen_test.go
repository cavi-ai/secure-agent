package wiregen

import (
	"os"
	"path/filepath"
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
