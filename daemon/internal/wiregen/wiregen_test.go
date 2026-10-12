package wiregen

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
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

func TestTypeScriptDistinguishesNullableFromOmittedPointers(t *testing.T) {
	type sample struct {
		Value string `json:"value"`
	}
	type wire struct {
		Present *sample `json:"present"`
		Count   *int    `json:"count"`
		Omitted *sample `json:"omitted,omitempty"`
	}
	ts := TypeScript(wire{})
	for _, field := range []string{"present: sample | null;", "count: number | null;", "omitted?: sample;"} {
		if !strings.Contains(ts, field) {
			t.Fatalf("wire nullability missing %q:\n%s", field, ts)
		}
	}
}

func interfaceBody(t *testing.T, ts, name string) string {
	t.Helper()
	marker := "export interface " + name + " {\n"
	_, rest, ok := strings.Cut(ts, marker)
	if !ok {
		t.Fatalf("missing interface %s", name)
	}
	body, _, ok := strings.Cut(rest, "}\n")
	if !ok {
		t.Fatalf("unterminated interface %s", name)
	}
	return body
}

func TestTypeScriptPreservesCollidingWireTypes(t *testing.T) {
	ts := Generate()
	for name, fields := range map[string][]string{
		"ApiSnapshot":      {"incidents: IncidentDetail[] | null;", "sessions: ModelSession[] | null;"},
		"ResourceSnapshot": {"sessions: ResourceSession[] | null;"},
		"ModelSession":     {"id: string;"},
		"ResourceSession":  {"key: string;"},
	} {
		body := interfaceBody(t, ts, name)
		for _, field := range fields {
			if !strings.Contains(body, field) {
				t.Errorf("%s missing %q", name, field)
			}
		}
	}
	for _, roots := range [][]any{
		{api.Snapshot{}, resource.Snapshot{}},
		{resource.Snapshot{}, api.Snapshot{}},
	} {
		ts := TypeScript(roots...)
		for _, name := range []string{"ApiSnapshot", "ResourceSnapshot", "ModelSession", "ResourceSession"} {
			if strings.Count(ts, "export interface "+name+" {") != 1 {
				t.Errorf("%s missing or duplicated", name)
			}
		}
	}
}

func TestTypeScriptSnapshotIncidentMatchesJSON(t *testing.T) {
	snapshot := reflect.TypeOf(api.Snapshot{})
	incidents, _ := snapshot.FieldByName("Incidents")
	incidentType := incidents.Type.Elem()
	payload, err := json.Marshal(reflect.New(incidentType).Interface())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	body := interfaceBody(t, Generate(), "IncidentDetail")
	for field := range fields {
		if !strings.Contains(body, "  "+field+":") && !strings.Contains(body, "  "+field+"?:") {
			t.Errorf("missing JSON field %s", field)
		}
	}
	if strings.Contains(body, "IncidentReport:") {
		t.Error("anonymous report must be flattened")
	}
	if !strings.Contains(body, "workflow: IncidentWorkflow;") {
		t.Error("missing incident workflow")
	}
}

func TestTypeScriptDiscoversCollectionStructs(t *testing.T) {
	type element struct {
		Value string `json:"value"`
	}
	type collections struct {
		Map    map[string]element `json:"map"`
		Array  [2]element         `json:"array"`
		Hidden element            `json:"-"`
	}
	ts := TypeScript(collections{})
	type mapContainer struct {
		Values map[string]element `json:"values"`
	}
	mapOnly := TypeScript(mapContainer{})
	if !strings.Contains(mapOnly, "export interface element {") {
		t.Error("map-only element missing")
	}
	if strings.Count(ts, "export interface element {") != 1 {
		t.Fatal("collection element missing or duplicated")
	}
	body := interfaceBody(t, ts, "collections")
	for _, field := range []string{"map: Record<string, element> | null;", "array: element[];"} {
		if !strings.Contains(body, field) {
			t.Errorf("missing %s", field)
		}
	}
}

func TestTypeScriptTaggedEmbeddingStaysNested(t *testing.T) {
	type wire struct {
		model.IncidentReport `json:"report"`
	}
	body := interfaceBody(t, TypeScript(wire{}), "wire")
	if strings.TrimSpace(body) != "report: IncidentReport;" {
		t.Fatalf("tagged embed flattened: %s", body)
	}
}

func TestTypeScriptEmbeddingResolvesJSONConflicts(t *testing.T) {
	type Left struct {
		Same  string
		Left  int  `json:"left"`
		Count *int `json:"count"`
	}
	type Right struct {
		Same  string
		Right int `json:"right"`
	}
	type ambiguous struct {
		Left
		Right
		hidden string
	}
	type overridden struct {
		Left
		Same int
	}
	type pointer struct{ *Left }
	type recursive struct {
		*recursive
		Value string `json:"value"`
	}
	for _, v := range []any{ambiguous{}, overridden{}, pointer{}, recursive{}} {
		payload, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]json.RawMessage
		if err := json.Unmarshal(payload, &actual); err != nil {
			t.Fatal(err)
		}
		ts := TypeScript(v)
		body := interfaceBody(t, ts, reflect.TypeOf(v).Name())
		generated := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			name, _, ok := strings.Cut(strings.TrimSpace(line), ":")
			if ok {
				generated[strings.TrimSuffix(name, "?")] = true
			}
		}
		// A nil anonymous pointer omits promoted fields; they must be optional.
		if _, ok := v.(pointer); ok {
			if !strings.Contains(body, "Same?: string;") || !strings.Contains(body, "left?: number;") || !strings.Contains(body, "count?: number | null;") {
				t.Fatal(body)
			}
			continue
		}
		if len(generated) != len(actual) {
			t.Fatalf("%T: schema keys %v != JSON %s", v, generated, payload)
		}
		for key := range actual {
			if !generated[key] {
				t.Fatalf("%T missing %s", v, key)
			}
		}
	}
}

func TestTypeScriptCollisionWithQualifiedName(t *testing.T) {
	type ApiSnapshot struct {
		Value string `json:"value"`
	}
	roots := []any{api.Snapshot{}, resource.Snapshot{}, ApiSnapshot{}}
	forward := TypeScript(roots...)
	reverse := TypeScript(roots[2], roots[1], roots[0])
	if !reflect.DeepEqual(Names(forward), Names(reverse)) {
		t.Fatal("names depend on root order")
	}
	seen := map[string]bool{}
	for _, name := range Names(forward) {
		if name == "" || seen[name] {
			t.Fatalf("invalid or duplicate declaration %q", name)
		}
		seen[name] = true
		if interfaceBody(t, forward, name) != interfaceBody(t, reverse, name) {
			t.Fatalf("%s changed shape with root order", name)
		}
	}
}

func TestGeneratedReferencesResolve(t *testing.T) {
	ts := Generate()
	declarations := map[string]bool{}
	for _, name := range Names(ts) {
		if name == "" || declarations[name] {
			t.Fatalf("invalid or duplicate declaration %q", name)
		}
		declarations[name] = true
	}
	builtins := map[string]bool{"string": true, "number": true, "boolean": true, "unknown": true, "null": true, "Record": true}
	identifiers := regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)
	for _, line := range strings.Split(ts, "\n") {
		if !strings.HasPrefix(line, "  ") {
			continue
		}
		_, typ, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("invalid field %q", line)
		}
		for _, name := range identifiers.FindAllString(typ, -1) {
			if !builtins[name] && !declarations[name] {
				t.Errorf("unresolved type %s in %q", name, line)
			}
		}
	}
}
