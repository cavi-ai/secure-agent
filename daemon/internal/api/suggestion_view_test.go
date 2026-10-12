package api

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type memorySuggestionVerdictReader struct {
	verdicts map[string]model.AdvisorVerdict
	err      error
	ids      []string
	kind     string
	reads    int
}

func (r *memorySuggestionVerdictReader) AdvisorVerdictsFor(ids []string, kind string) (map[string]model.AdvisorVerdict, error) {
	r.ids, r.kind = slices.Clone(ids), kind
	r.reads++
	return r.verdicts, r.err
}

func TestSuggestionReaderFiltersAndBatchesCandidates(t *testing.T) {
	endpoints := []correlate.UninspectedSummary{
		{Agent: "agent", Host: "rare.example", Count: minSuggestionCount - 1},
		{Agent: "agent", Host: "carrier.example", Count: 10, Infra: "carrier"},
		{Agent: "agent", Host: "vendor.example", Count: 10, Identity: hostid.EndpointIdentity{Class: "vendor"}},
		{Agent: "infra", Host: "shared.example", Count: 10, AgentKind: config.AgentKindInfra},
		{Agent: "agent-b", Host: "frequent.example", Count: 5, Identity: hostid.EndpointIdentity{Class: "unknown"}},
		{Agent: "agent-a", Host: "boundary.example", Count: minSuggestionCount},
	}
	before := slices.Clone(endpoints)
	r := &memorySuggestionVerdictReader{verdicts: map[string]model.AdvisorVerdict{
		"host:agent-b|frequent.example": {Assessment: "expected", Rationale: "Known destination", Confidence: 0.8},
		"host:agent|vendor.example":     {Assessment: "suspicious"},
	}}
	rows, err := readEgressSuggestions(r, endpoints)
	want := []Suggestion{
		{Agent: "agent-b", Host: "frequent.example", Count: 5, Identity: endpoints[4].Identity, Assessment: "expected", Rationale: "Known destination", Confidence: 0.8},
		{Agent: "agent-a", Host: "boundary.example", Count: minSuggestionCount},
	}
	if err != nil || !reflect.DeepEqual(rows, want) || !reflect.DeepEqual(endpoints, before) {
		t.Fatalf("candidate order, facts, or source changed: %+v, %v", rows, err)
	}
	if r.reads != 1 || r.kind != "host" || !slices.Equal(r.ids, []string{"host:agent-b|frequent.example", "host:agent-a|boundary.example"}) {
		t.Fatalf("advisor batch included unrelated candidates: %+v", r)
	}
}

func TestSuggestionReaderRetainsHealthyAdviceAndRecovers(t *testing.T) {
	failed := errors.New("host advice unavailable")
	endpoints := []correlate.UninspectedSummary{
		{Agent: "agent", Host: "first.example", Count: 4},
		{Agent: "agent", Host: "second.example", Count: 3},
	}
	for _, healthySibling := range []bool{false, true} {
		r := &memorySuggestionVerdictReader{err: failed, verdicts: map[string]model.AdvisorVerdict{}}
		if healthySibling {
			r.verdicts["host:agent|second.example"] = model.AdvisorVerdict{Assessment: "expected", Rationale: "Known destination", Confidence: 0.9}
		}
		rows, err := readEgressSuggestions(r, endpoints)
		want := []Suggestion{{Agent: "agent", Host: "first.example", Count: 4}, {Agent: "agent", Host: "second.example", Count: 3}}
		if healthySibling {
			want[1].Assessment, want[1].Rationale, want[1].Confidence = "expected", "Known destination", 0.9
		}
		if !errors.Is(err, failed) || !reflect.DeepEqual(rows, want) || r.reads != 1 {
			t.Fatalf("failed enrichment changed observations or healthy advice: %+v, %v", rows, err)
		}
		r.err = nil
		r.verdicts["host:agent|first.example"] = model.AdvisorVerdict{Assessment: "suspicious", Rationale: "Unknown destination", Confidence: 0.7}
		rows, err = readEgressSuggestions(r, endpoints)
		want[0].Assessment, want[0].Rationale, want[0].Confidence = "suspicious", "Unknown destination", 0.7
		if err != nil || !reflect.DeepEqual(rows, want) || r.reads != 2 {
			t.Fatalf("new read did not recover advice: %+v, %v", rows, err)
		}
	}
}

func TestSuggestionReaderEmptyAndExcludedEndpoints(t *testing.T) {
	for _, endpoints := range [][]correlate.UninspectedSummary{nil, {{Agent: "agent", Host: "rare.example", Count: 2}}} {
		r := &memorySuggestionVerdictReader{}
		rows, err := readEgressSuggestions(r, endpoints)
		if err != nil || rows == nil || len(rows) != 0 || r.reads != 1 || len(r.ids) != 0 || r.kind != "host" {
			t.Fatalf("empty candidate batch: %+v, %v, reader=%+v", rows, err, r)
		}
	}
}
