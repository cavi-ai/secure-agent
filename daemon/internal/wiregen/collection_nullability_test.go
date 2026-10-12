package wiregen

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestTypeScriptCollectionNullabilityMatchesJSON(t *testing.T) {
	type collectionValue struct {
		Value string `json:"value"`
	}
	type collections struct {
		Slice        []string                    `json:"slice"`
		Map          map[string]string           `json:"map"`
		Array        [1]string                   `json:"array"`
		OmittedSlice []string                    `json:"omitted_slice,omitempty"`
		OmittedMap   map[string]string           `json:"omitted_map,omitempty"`
		Items        []*collectionValue          `json:"items"`
		Values       map[string]*collectionValue `json:"values"`
		Fixed        [1]*collectionValue         `json:"fixed"`
		Nested       [][]string                  `json:"nested"`
		Pointer      *[]string                   `json:"pointer,omitempty"`
	}
	var nilSlice []string
	fixture := collections{Items: []*collectionValue{nil}, Values: map[string]*collectionValue{"nil": nil}, Nested: [][]string{nil, {}}, Pointer: &nilSlice}
	payload, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"slice":null,"map":null,"array":[""],"items":[null],"values":{"nil":null},"fixed":[null],"nested":[null,[]],"pointer":null}`
	if string(payload) != expected {
		t.Fatalf("fixture JSON changed: %s", payload)
	}
	body := interfaceBody(t, TypeScript(collections{}), "collections")
	for _, field := range []string{
		"slice: string[] | null;", "map: Record<string, string> | null;", "array: string[];",
		"omitted_slice?: string[];", "omitted_map?: Record<string, string>;",
		"items: (collectionValue | null)[] | null;", "values: Record<string, collectionValue | null> | null;",
		"fixed: (collectionValue | null)[];", "nested: (string[] | null)[] | null;", "pointer?: string[] | null;",
	} {
		if !strings.Contains(body, field) {
			t.Errorf("missing %q in schema:\n%s", field, body)
		}
	}
	empty, err := json.Marshal(collections{Slice: []string{}, Map: map[string]string{}, OmittedSlice: []string{}, OmittedMap: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(empty, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["slice"]) != "[]" || string(fields["map"]) != "{}" {
		t.Fatalf("empty collection shape: %s", empty)
	}
	for _, key := range []string{"omitted_slice", "omitted_map", "pointer"} {
		if _, present := fields[key]; present {
			t.Fatalf("%s should be omitted: %s", key, empty)
		}
	}
}

func TestTypeScriptIncidentCollectionsAcceptWireNull(t *testing.T) {
	payload, err := json.Marshal(model.IncidentReport{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	body := interfaceBody(t, Generate(), "IncidentReport")
	for _, field := range []string{"touched_files", "connections", "rotate_list"} {
		if string(fields[field]) != "null" {
			t.Fatalf("%s JSON changed: %s", field, payload)
		}
		var line string
		for _, candidate := range strings.Split(body, "\n") {
			if strings.HasPrefix(candidate, "  "+field+":") {
				line = candidate
			}
		}
		if !strings.HasSuffix(line, "[] | null;") {
			t.Errorf("%s excludes actual JSON null: %s", field, line)
		}
	}
}
