package routegen

import (
	"os"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
)

func TestGeneratedRouteBindingsMatchTable(t *testing.T) {
	want, err := Generate(apiroutes.Table)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../api/routes_generated.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("route bindings stale: run go generate ./daemon/internal/apiroutes")
	}
	for _, fragment := range []string{"a.handlePosture", "a.serveSessionOutcomes", "new(SessionOutcomes)"} {
		if !strings.Contains(string(got), fragment) {
			t.Fatalf("missing binding %s", fragment)
		}
	}
}
