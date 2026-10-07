package store

import (
	"go/build"
	"strings"
	"testing"
)

// The store persists what the engines produce; it imports none of them, so
// an engine can read the store without an import cycle.
func TestStoreImportsNoDetectionEngine(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		for _, engine := range []string{"/internal/correlate", "/internal/firewall", "/internal/advisor", "/internal/api"} {
			if strings.HasSuffix(imp, engine) {
				t.Errorf("store imports %s", imp)
			}
		}
	}
}
