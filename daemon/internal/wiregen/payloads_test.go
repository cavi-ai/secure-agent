package wiregen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
)

func TestSwiftPayloadsDrift(t *testing.T) {
	path := filepath.Join("..", "..", "..", "menubar", "Tests", "SecureAgentMenubarTests", "WirePayloads.swift")
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	generated, err := GenerateSwift()
	if err != nil {
		t.Fatal(err)
	}
	if generated != string(committed) {
		t.Fatalf("WirePayloads.swift is stale — regenerate with: go run ./cmd/genwire (from daemon/)")
	}
}

func TestRoutePayloadsCoverEveryTypedRoute(t *testing.T) {
	payloads, err := RoutePayloads()
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]RoutePayload{}
	for _, p := range payloads {
		byPath[p.Path] = p
	}
	want := 0
	for _, r := range apiroutes.Table {
		if r.Response != "" {
			want++
			if _, ok := byPath[r.Path]; !ok {
				t.Errorf("%s: no payload", r.Path)
			}
		}
		for _, leaf := range r.Leaves {
			if leaf.Response != "" {
				want++
				if _, ok := byPath[r.Path+"{id}/"+leaf.Path]; !ok {
					t.Errorf("%s{id}/%s: no payload", r.Path, leaf.Path)
				}
			}
		}
	}
	if len(payloads) != want {
		t.Fatalf("%d payloads for %d typed routes", len(payloads), want)
	}
}

// A full payload carries a value for every key, so a client field the daemon
// can send is never satisfied by an absent or null key.
func TestFullRoutePayloadsHaveNoNulls(t *testing.T) {
	payloads, err := RoutePayloads()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range payloads {
		var v any
		if err := json.Unmarshal(p.Full, &v); err != nil {
			t.Fatalf("%s: %v", p.Path, err)
		}
		for _, at := range nullPaths(v, "$") {
			t.Errorf("%s: null at %s", p.Path, at)
		}
	}
}

func TestSampleStopsRecursiveTypes(t *testing.T) {
	type node struct {
		Name string
		Map  map[string]node
		List []*node
		Next *node
	}
	got, err := json.Marshal(sample(reflect.TypeOf(node{}), map[reflect.Type]bool{}).Interface())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Name":"x","Map":{},"List":[],"Next":null}`
	if string(got) != want {
		t.Fatalf("sample = %s", got)
	}
}

func nullPaths(v any, at string) []string {
	switch x := v.(type) {
	case nil:
		return []string{at}
	case map[string]any:
		var out []string
		for k, e := range x {
			out = append(out, nullPaths(e, at+"."+k)...)
		}
		return out
	case []any:
		var out []string
		for i, e := range x {
			out = append(out, nullPaths(e, fmt.Sprintf("%s[%d]", at, i))...)
		}
		return out
	}
	return nil
}
